import logging
import os
from openai import OpenAI
from openai.types.chat import ChatCompletion
from pydantic import BaseModel

from prompts.ioc_extracting_prompts import ioc_extracting_system_prompt, generate_ioc_extracting_user_prompt
from utils import strip_value


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

    @staticmethod
    def _validate_ip_addresses(ip_addresses: list[str]) -> str | list[str]:
        def _is_valid_ip_address(ip_address: str) -> bool:
            host_bytes = ip_address.split('.')

            # Check if there are exactly 4 segments
            if len(host_bytes) != 4:
                return False

            # Check if all segments are valid integers in the range 0-255
            for byte in host_bytes:
                if not byte.isdigit() or not 0 <= int(byte) <= 255:
                    return False

            return True
        seen = set()
        results = []
        for ip_address in ip_addresses:
            ip_address = ip_address.replace('[', '').replace(']', '').replace('(', '').replace(')', '').replace('"', '').replace("'", '').strip()
            if _is_valid_ip_address(ip_address) and ip_address not in seen:
                seen.add(ip_address)
                results.append(ip_address)

        if len(results) == 1:
            return results[0]
        return results

    @staticmethod
    def _validate_user_agents(user_agents: list[str]) -> str | list[str]:
        seen = set()
        results = []
        for user_agent in user_agents:
            user_agent = strip_value(user_agent)
            if user_agent not in seen and user_agent != 'AWS Internal':  # TODO: Implement custom integration for "AWS Internal"
                seen.add(user_agent)
                results.append(user_agent)

        if len(results) == 1:
            return results[0]
        return results

    @staticmethod
    def _validate_ioc(ioc: IOC) -> IOC:
        ioc.ip_addresses = IOCExtractor._validate_ip_addresses(ioc.ip_addresses)
        ioc.user_agents = IOCExtractor._validate_user_agents(ioc.user_agents)

        return ioc

    def extract_iocs(self, markdown: str) -> IOC | None:
        messages = IOCExtractor._generate_iocs_extraction_messages(markdown)

        try:
            response = self._send_iocs_extraction_request(messages)
        except Exception as e:
            logging.error(f"Error extracting IOCs: {e}")
            return None

        ioc = response.choices[0].message.parsed
        ioc = IOCExtractor._validate_ioc(ioc)

        return ioc
