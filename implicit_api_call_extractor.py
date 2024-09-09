import json
import logging
import os
from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.implicit_events_extracting_prompts import implicit_event_names_extracting_system_prompt, generate_implicit_event_names_extracting_user_prompt
from utils import sanitize_event


class ImplicitApiCallExtractor:
    def __init__(self, model_name: str = 'chatgpt-4o-latest', api_key: str = None, temperature: float = 0.9, number_of_runs: int = 7, threshold: int = 6):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature
        self.number_of_runs = number_of_runs
        self.threshold = threshold

    @staticmethod
    def _generate_implicit_api_call_extraction_messages(paragraph: str) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": implicit_event_names_extracting_system_prompt},
            {"role": "user", "content": generate_implicit_event_names_extracting_user_prompt(paragraph)}
        ]

    def _send_implicit_api_call_extraction_request(self, messages: list[dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            messages=messages,
            response_format={"type": "json_object"}
        )

    def extract_implicit_api_calls(self, paragraph: str, explicit_event_to_source: dict[str, str]) -> dict[str, str] | None:
        final_implicit_event_to_source = {}
        implicit_events_counter = {}

        for i in range(self.number_of_runs):
            messages = ImplicitApiCallExtractor._generate_implicit_api_call_extraction_messages(paragraph)

            try:
                response = self._send_implicit_api_call_extraction_request(messages)
            except Exception as e:
                logging.error(f"Error extracting implicit API calls: {e}")
                return None

            response = response.choices[0].message.content
            implicit_event_to_source = json.loads(response)

            for implicit_event, source in implicit_event_to_source.items():
                # sanitized_implicit_event = sanitize_event(implicit_event)
                # if sanitized_implicit_event not in explicit_event_to_source:
                #     final_implicit_event_to_source[sanitized_implicit_event] = source
                #     implicit_events_counter[sanitized_implicit_event] = implicit_events_counter.get(sanitized_implicit_event, 0) + 1
                if implicit_event not in explicit_event_to_source:
                    final_implicit_event_to_source[implicit_event] = source
                    implicit_events_counter[implicit_event] = implicit_events_counter.get(implicit_event, 0) + 1

            if i == self.number_of_runs - self.threshold and not final_implicit_event_to_source:
                break

        implicit_events_to_remove = [implicit_event for implicit_event, count in implicit_events_counter.items() if count < self.threshold]

        for implicit_event in implicit_events_to_remove:
            del final_implicit_event_to_source[implicit_event]

        return final_implicit_event_to_source
