import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.rule_optimizing_prompts import rule_optimizing_system_prompt, generate_rule_optimizing_user_prompt


class RuleOptimizer:
    def __init__(self, model_name: str = 'chatgpt-4o-latest', api_key: str = None, temperature: float = 0.5):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature

    @staticmethod
    def _generate_optimization_messages(rule: dict) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": rule_optimizing_system_prompt},
            {"role": "user", "content": generate_rule_optimizing_user_prompt(rule)}
        ]

    def _send_optimization_request(self, messages: list[dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            messages=messages,
            response_format={"type": "json_object"}
        )

    def _optimize_rule(self, rule: dict) -> dict | None:
        messages = self._generate_optimization_messages(rule)

        try:
            response = self._send_optimization_request(messages)
        except Exception as e:
            logging.error(f"Error optimizing rule: {e}")
            return None

        response = response.choices[0].message.content
        rule = json.loads(response)

        return rule

    def optimize_rules(self, rules: dict | list[dict]) -> list[dict] | None:
        if isinstance(rules, dict):
            rules = [rules]
        results = [None] * len(rules)
        with ThreadPoolExecutor() as executor:
            future_to_index = {executor.submit(self._optimize_rule, rule): index for index, rule in enumerate(rules)}
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                rule = future.result()
                results[index] = rule

        results = [result for result in results if result is not None]
        if results:
            return results

        return None
