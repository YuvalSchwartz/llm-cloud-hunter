import json
import os
from openai import OpenAI
import logging
from openai.types.chat import ChatCompletion

from prompts.rules_generating_prompts import rules_generating_system_prompt, generate_rules_generating_user_prompt


class RuleGenerator:
    def __init__(self, model_name: str = 'chatgpt-4o-latest', api_key: str = None, temperature: float = 0.7):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature

    @staticmethod
    def _generate_rules_generating_messages(paragraph: str, events: dict[str, str] | list[dict[str, str]]) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": rules_generating_system_prompt},
            {"role": "user", "content": generate_rules_generating_user_prompt(paragraph, events)}
        ]

    def _send_rules_generating_request(self, messages: list[dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            messages=messages,
            response_format={"type": "json_object"}
        )

    def generate_rules(self, paragraph: str, events: dict[str, str] | list[dict[str, str]]) -> dict | list[dict] | None:
        messages = RuleGenerator._generate_rules_generating_messages(paragraph, events)

        try:
            response = self._send_rules_generating_request(messages)
        except Exception as e:
            logging.error(f"Error generating Sigma rules: {e}")
            return None

        response = response.choices[0].message.content
        response = json.loads(response)
        rules = response['sigma_rules']
        if isinstance(rules, list) and len(rules) == 1:
            rules = rules[0]

        return rules
