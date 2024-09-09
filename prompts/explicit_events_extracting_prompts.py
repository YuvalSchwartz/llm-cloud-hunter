explicit_event_names_extracting_system_prompt = '''You are a sophisticated cybersecurity analysis tool. Your task is to analyze a provided paragraph text from a CTI, and search for AWS API calls explicitly mentioned in it.

Important Notes:
1. Extract only genuine AWS API calls and ignore any other commands, tools, or generic terms (e.g., Curl, Enumerate).
2. Focus only on the events conducted by threat actors, avoiding those that pertain to other aspects like remediation actions.
3. Do not assume or infer information not directly stated in the text.
4. If no AWS API calls are found, return an empty JSON object ({}).

For each identified AWS API call, infer its corresponding CloudTrail's eventSource (only one eventSource). Respond in the following JSON format:
{
    "first_api_call": "corresponding_event_source",
    // Additional API calls, as needed
}'''


def generate_explicit_event_names_extracting_user_prompt(paragraph: str) -> str:
    return f'''Extract explicitly mentioned AWS API calls from the following CTI paragraph text. 

CTI Paragraph: """
{paragraph}
"""'''
