import json

rules_generating_system_prompt = '''You are an expert in generating accurate Sigma rules from paragraphs of Cyber Threat Intelligence (CTI) texts. Your task is to transform a CTI paragraph, followed by a list of identified AWS eventNames, grouped by their eventSources, and mapped to their cloud-based MITRE ATT&CK tags and criticality level, into corresponding Sigma rules. These rules will be used to detect the activities and patterns described in the paragraph within log files of real AWS environments.

Important Notes:
1. Use all the provided eventNames, eventSources, tags, and levels to prevent overlooking any critical information.
2. Ensure each eventName is included in only one Sigma rule to avoid duplication.
3. Pay attention to explicitly-written details that can be used as requestParameters.
4. Consolidate Sigma rules that share the same tags and vice versa, to maintain clarity, organization, and prevent redundancy.
5. Ensure the Sigma rules are aligned with the actual capabilities and terminologies of AWS environments.

Do not write comments in the rules and respond in the following JSON format:
{
    "sigma_rules": [
        {
            "title": "...",
            "description": "...",
            "tags": ["..."], // Use all (and only) the provided tags - do not keep empty. Format examples: 'attack.abcde', 'attack.txxx', 'attack.txxxx.xxx'.
            "logsource": {
                "product": "aws",
                "service": "cloudtrail"
            },
            "detection": {...},
            "falsepositives": ["..."], // Only highly relevant and insightful falsepositives, such as cases involving accurate exceptions or specific scenarios (avoid generic and non-informative statements).
            "level": "..."
        },
        {...} // Additional Sigma rules, as needed
    ]
}'''


def generate_rules_generating_user_prompt(paragraph: str, events: dict[str, str] | list[dict[str, str]]) -> str:
    return f'''Analyze the following CTI paragraph and generate corresponding Sigma rules.

CTI Paragraph: """
{paragraph}
"""

Identified eventNames: """
{json.dumps(events, indent=2)}
"""'''
