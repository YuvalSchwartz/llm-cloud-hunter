import logging
import os
from openai import OpenAI
from openai.types.chat import ChatCompletion
from pydantic import BaseModel

from prompts.rule_selecting_prompts import rule_selecting_system_prompt, generate_rule_selecting_user_prompt


class RuleSelection(BaseModel):
    selected_sigma_rule_id: int


class RuleSelector:
    def __init__(self, model_name: str = 'gpt-4o-2024-08-06', api_key: str = None, temperature: float = 0.5):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature

    @staticmethod
    def _generate_selection_messages(event_names_list, sigma_rules_indexes_and_objects_list) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": rule_selecting_system_prompt},
            {"role": "user", "content": generate_rule_selecting_user_prompt(event_names_list, sigma_rules_indexes_and_objects_list)}
        ]

    def _send_selection_request(self, messages: list[dict[str, str]]) -> ChatCompletion:
        return self.client.beta.chat.completions.parse(
            model=self.model_name,
            temperature=self.temperature,
            messages=messages,
            response_format=RuleSelection
        )

    def select_rule(self, event_names_list, sigma_rules_indexes_and_objects_list) -> int | None:
        messages = RuleSelector._generate_selection_messages(event_names_list, sigma_rules_indexes_and_objects_list)

        try:
            response = self._send_selection_request(messages)
        except Exception as e:
            logging.error(f"Error selecting rule: {e}")
            return None

        return response.choices[0].message.parsed.selected_sigma_rule_id
