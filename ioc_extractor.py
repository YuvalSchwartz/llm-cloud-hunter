import logging
import os
from openai import OpenAI
from openai.types.chat import ChatCompletion
from pydantic import BaseModel

from prompts.ioc_extracting_prompts import ioc_extracting_system_prompt, generate_ioc_extracting_user_prompt


class IOC(BaseModel):
    ip_addresses: list[str]
    user_agents: list[str]


class IOCExtractor:
    def __init__(self, model_name: str = 'gpt-4o-2024-08-06', api_key: str = None, temperature: float = 0.5):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature

    @staticmethod
    def _generate_iocs_extraction_messages(markdown: str) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": ioc_extracting_system_prompt},
            {"role": "user", "content": generate_ioc_extracting_user_prompt(markdown)}
        ]

    def _send_iocs_extraction_request(self, messages: list[dict[str, str]]) -> ChatCompletion:
        return self.client.beta.chat.completions.parse(
            model=self.model_name,
            temperature=self.temperature,
            messages=messages,
            response_format=IOC
        )

    def extract_iocs(self, markdown: str) -> dict[str, str | list[str]] | None:
        messages = IOCExtractor._generate_iocs_extraction_messages(markdown)

        try:
            response = self._send_iocs_extraction_request(messages)
        except Exception as e:
            logging.error(f"Error extracting IOCs: {e}")
            return None

        return response.choices[0].message.parsed
