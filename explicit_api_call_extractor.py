import json
import logging
import os
from typing import Dict, List
from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.explicit_events_extracting_prompts import explicit_event_names_extracting_system_prompt, generate_explicit_event_names_extracting_user_prompt
from utils import sanitize_event


class ExplicitApiCallExtractor:
    def __init__(self, model_name: str = None, api_key: str = None, temperature: float = 0, number_of_runs=3, threshold=2):
        self.model_name = model_name if model_name else "gpt-4o"
        api_key = api_key if api_key else os.getenv('OPENAI_API_KEY')
        self.client = OpenAI(api_key=api_key)
        self.temperature = temperature
        self.number_of_runs = number_of_runs
        self.threshold = threshold

    @staticmethod
    def _generate_explicit_api_call_extraction_messages(paragraph: str) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": explicit_event_names_extracting_system_prompt},
            {"role": "user", "content": generate_explicit_event_names_extracting_user_prompt(paragraph)}
        ]

    def _send_explicit_api_call_extraction_request(self, messages: List[Dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=messages
        )

    def extract_explicit_api_calls(self, paragraph: str) -> Dict[str, str] | None:
        final_explicit_event_to_source = {}
        explicit_events_counter = {}

        for i in range(self.number_of_runs):
            messages = ExplicitApiCallExtractor._generate_explicit_api_call_extraction_messages(paragraph)

            try:
                response = self._send_explicit_api_call_extraction_request(messages)
            except Exception as e:
                logging.error(f"Error extracting explicit API calls: {e}")
                return None

            response = response.choices[0].message.content
            explicit_event_to_source = json.loads(response)

            for explicit_event, source in explicit_event_to_source.items():
                # TODO: Uncomment the following line and comment the line after it
                # sanitized_explicit_event = sanitize_event(explicit_event)
                # final_explicit_event_to_source[sanitized_explicit_event] = source
                # explicit_events_counter[sanitized_explicit_event] = explicit_events_counter.get(sanitized_explicit_event, 0) + 1
                final_explicit_event_to_source[explicit_event] = source
                explicit_events_counter[explicit_event] = explicit_events_counter.get(explicit_event, 0) + 1
                # TODO: Uncomment the above line and comment the line before it

            if i == self.number_of_runs - self.threshold + 1 and not explicit_event_to_source:
                break

        explicit_events_to_remove = [explicit_event for explicit_event, count in explicit_events_counter.items() if count < self.threshold]

        for explicit_event in explicit_events_to_remove:
            del final_explicit_event_to_source[explicit_event]

        return final_explicit_event_to_source
