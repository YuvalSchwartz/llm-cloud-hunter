import json
import logging
import os
from typing import List, Dict

from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.rule_selecting_prompts import rule_selecting_system_prompt, generate_rule_selecting_user_prompt


class RuleSelector:
    def __init__(self, model_name: str = None, api_key: str = None, temperature: float = 0.5):
        self.model_name = model_name if model_name else "gpt-4o"
        api_key = api_key if api_key else os.getenv('OPENAI_API_KEY')
        self.client = OpenAI(api_key=api_key)
        self.temperature = temperature

    @staticmethod
    def _generate_selection_messages(event_names_list, sigma_rules_indexes_and_objects_list) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": rule_selecting_system_prompt},
            {"role": "user", "content": generate_rule_selecting_user_prompt(event_names_list, sigma_rules_indexes_and_objects_list)}
        ]

    def _send_selection_request(self, messages: List[Dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=messages
        )

    def select_rule(self, event_names_list, sigma_rules_indexes_and_objects_list) -> int | None:
        messages = RuleSelector._generate_selection_messages(event_names_list, sigma_rules_indexes_and_objects_list)

        try:
            response = self._send_selection_request(messages)
        except Exception as e:
            logging.error(f"Error selecting rule: {e}")
            return None

        response = response.choices[0].message.content
        response = json.loads(response)
        rule_id = int(response['selected_sigma_rule_id'])

        return rule_id
