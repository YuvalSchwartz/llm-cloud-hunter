from typing import Dict, List
import json

criticality_classification_system_prompt = """You are a sophisticated cybersecurity analysis tool, specialized in classifying threat actors' API calls based on their criticality. Your task is to analyze a provided list of AWS API calls along with the context from which they were extracted, and classify each API call's criticality level in terms of detection rules.

Criticality Levels:
1. low
2. medium
3. high

Important Notes:
1. Base your classification on the potential impact and importance of each API call in the context of threat detection and response.
2. Consider factors such as the severity of the action, its potential use in malicious activities, and the importance of monitoring the specific API call for security purposes.
3. Do not assume or infer information not directly provided.
5. Do not add comments, explanations, or justifications in the response.

For each API call, respond in the following JSON format:
{
    "first_api_call": "...",
    // Additional API calls, as needed
}"""


def generate_criticality_classification_user_prompt(events: Dict[str, str] | List[Dict[str, str]], paragraph: str) -> str:
    return f"""Classify the following AWS API calls based on their criticality level.

API calls:
----------------
{json.dumps(events)}
----------------

The context from which the API calls were extracted:
----------------
{paragraph}
----------------"""
