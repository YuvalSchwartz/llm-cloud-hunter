import json
import logging
import os
from typing import List, Dict, Any

from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.events_removing_prompts import events_removing_system_prompt, generate_events_removing_user_prompt


class EventsRemover:
    def __init__(self, model_name: str = None, api_key: str = None, temperature: float = 0.5):
        self.model_name = model_name if model_name else "gpt-4o"
        api_key = api_key if api_key else os.getenv('OPENAI_API_KEY')
        self.client = OpenAI(api_key=api_key)
        self.temperature = temperature

    @staticmethod
    def _generate_messages(event_names_list, rule) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": events_removing_system_prompt},
            {"role": "user", "content": generate_events_removing_user_prompt(event_names_list, rule)}
        ]

    def _send_events_removing_request(self, messages: List[Dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=messages
        )

    def remove_events(self, event_names_list: List[str], rule: Dict[str, Any]) -> Dict | None:
        messages = EventsRemover._generate_messages(event_names_list, rule)

        try:
            response = self._send_events_removing_request(messages)
        except Exception as e:
            logging.error(f"Error removing events: {e}")
            return None

        response = response.choices[0].message.content
        rule = json.loads(response)

        return rule
