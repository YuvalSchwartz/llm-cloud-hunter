import json
import logging
import os
from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.criticality_classification_prompts import criticality_classification_system_prompt, generate_criticality_classification_user_prompt
from utils import validate_event


class CriticalityClassifier:
    def __init__(self, model_name: str = 'chatgpt-4o-latest', api_key: str = None, temperature: float = 0.5):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature

    @staticmethod
    def _generate_criticality_classification_messages(events: dict[str, str] | list[dict[str, str]], paragraph: str) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": criticality_classification_system_prompt},
            {"role": "user", "content": generate_criticality_classification_user_prompt(events, paragraph)}
        ]

    def _send_criticality_classification_request(self, messages: list[dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            messages=messages,
            response_format={"type": "json_object"}
        )

    def classify_api_call_criticality(self, events: dict[str, str] | list[dict[str, str]], paragraph: str) -> dict[str, str] | None:
        messages = self._generate_criticality_classification_messages(events, paragraph)

        try:
            response = self._send_criticality_classification_request(messages)
        except Exception as e:
            logging.error(f"Error classifying criticality: {e}")
            return None

        response = response.choices[0].message.content
        event_to_criticality = json.loads(response)
        event_to_criticality = {validate_event(event): criticality for event, criticality in event_to_criticality.items()}

        return event_to_criticality
