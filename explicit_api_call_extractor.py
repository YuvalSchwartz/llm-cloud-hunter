import json
import logging
import os
from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.explicit_events_extracting_prompts import explicit_event_names_extracting_system_prompt, generate_explicit_event_names_extracting_user_prompt
from utils import validate_event


class ExplicitApiCallExtractor:
    def __init__(self, model_name: str = 'chatgpt-4o-latest', api_key: str = None, temperature: float = 0, number_of_runs: int = 3, threshold: int = 2):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature
        self.number_of_runs = number_of_runs
        self.threshold = threshold

    @staticmethod
    def _generate_explicit_api_call_extraction_messages(paragraph: str) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": explicit_event_names_extracting_system_prompt},
            {"role": "user", "content": generate_explicit_event_names_extracting_user_prompt(paragraph)}
        ]

    def _send_explicit_api_call_extraction_request(self, messages: list[dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            messages=messages,
            response_format={"type": "json_object"}
        )

    def extract_explicit_api_calls(self, paragraph: str) -> dict[str, str] | None:
        messages = ExplicitApiCallExtractor._generate_explicit_api_call_extraction_messages(paragraph)

        final_explicit_event_to_source = {}
        explicit_events_counter = {}

        for i in range(self.number_of_runs):
            try:
                response = self._send_explicit_api_call_extraction_request(messages)
            except Exception as e:
                logging.error(f"Error extracting explicit API calls: {e}")
                return None

            response = response.choices[0].message.content
            explicit_event_to_source = json.loads(response)

            for explicit_event, source in explicit_event_to_source.items():
                reformatted_explicit_event = validate_event(explicit_event)
                final_explicit_event_to_source[reformatted_explicit_event] = source
                explicit_events_counter[reformatted_explicit_event] = explicit_events_counter.get(reformatted_explicit_event, 0) + 1

            if i == self.number_of_runs - self.threshold + 1 and not explicit_event_to_source:
                break

        explicit_events_to_remove = [explicit_event for explicit_event, count in explicit_events_counter.items() if count < self.threshold]
        for explicit_event in explicit_events_to_remove:
            del final_explicit_event_to_source[explicit_event]

        return final_explicit_event_to_source
