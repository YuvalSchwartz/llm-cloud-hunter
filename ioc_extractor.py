import json
import logging
import os
from typing import List, Dict

from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.ioc_extracting_prompts import ioc_extracting_system_prompt, generate_ioc_extracting_user_prompt


class IOCExtractor:
    def __init__(self, model_name: str = None, api_key: str = None, temperature: float = 0.5):
        self.model_name = model_name if model_name else "gpt-4o"
        api_key = api_key if api_key else os.getenv('OPENAI_API_KEY')
        self.client = OpenAI(api_key=api_key)
        self.temperature = temperature

    @staticmethod
    def _generate_iocs_extraction_messages(markdown: str) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": ioc_extracting_system_prompt},
            {"role": "user", "content": generate_ioc_extracting_user_prompt(markdown)}
        ]

    def _send_iocs_extraction_request(self, messages: List[Dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=messages
        )

    def extract_iocs(self, markdown: str) -> Dict[str, str | List[str]] | None:
        messages = IOCExtractor._generate_iocs_extraction_messages(markdown)

        try:
            response = self._send_iocs_extraction_request(messages)
        except Exception as e:
            logging.error(f"Error extracting IOCs: {e}")
            return None

        response = response.choices[0].message.content
        ioc = json.loads(response)

        return ioc
