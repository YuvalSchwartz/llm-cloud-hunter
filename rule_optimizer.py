import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List
from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.rule_optimizing_prompts import rule_optimizing_system_prompt, generate_rule_optimizing_user_prompt


class RuleOptimizer:
    def __init__(self, model=None, api_key=None, temperature=0.5):
        self.model = model if model else "gpt-4o"
        api_key = api_key if api_key else os.getenv('OPENAI_API_KEY')
        self.client = OpenAI(api_key=api_key)
        self.temperature = temperature

    @staticmethod
    def _generate_optimization_messages(rule: Dict) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": rule_optimizing_system_prompt},
            {"role": "user", "content": generate_rule_optimizing_user_prompt(rule)}
        ]

    def _send_optimization_request(self, messages: List[Dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=messages
        )

    def _optimize_rule(self, rule: dict) -> Dict | None:
        messages = self._generate_optimization_messages(rule)

        try:
            response = self._send_optimization_request(messages)
        except Exception as e:
            logging.error(f"Error optimizing rule: {e}")
            return None

        response = response.choices[0].message.content
        rule = json.loads(response)

        return rule

    def optimize_rules(self, rules: Dict | List[Dict]) -> List[Dict] | None:
        if isinstance(rules, Dict):
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
