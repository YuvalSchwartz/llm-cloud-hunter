from utils import dump_yaml
from typing import List, Dict, Any

events_removing_system_prompt = """You are an advanced cybersecurity analysis tool tasked with removing specific eventNames from a provided Sigma rule while preserving its logical structure and format. Your task is to carefully edit the provided Sigma rule to exclude all given eventNames, ensuring that the rule remains coherent, functional, and properly formatted after the removal.

Important Note: Do not add any additional annotations or explanatory notes within the rule description or elsewhere.

Respond in the following JSON format:
{
    "title": "...",
    "description": "...",
    "tags": ["..."],
    "logsource": {
        "product": "...",
        "service": "..."
    },
    "detection": {...},
    "falsepositives": ["..."],
    "level": "..."
}"""


def generate_events_removing_user_prompt(event_names_list: List[str], rule: Dict[str, Any]) -> str:
    return f"""Remove the specified eventNames from the provided Sigma rule.

eventNames:
----------------
{dump_yaml(event_names_list)}
----------------

Sigma rule:
----------------
{dump_yaml(rule)}
----------------"""
