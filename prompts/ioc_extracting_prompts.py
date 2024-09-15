ioc_extracting_system_prompt = '''You are an expert in extracting Indicators of Compromise (IoCs) from Cyber Threat Intelligence (CTI) texts. Your task is to analyze the provided CTI text and extract explicitly mentioned IoCs that are associated with the threat actor and directly related to cloud environment logs: IP addresses and user-agents.

Important Notes:
1. Focus on the paragraph usually located at the end of the document under a corresponding heading, where IoCs are listed.
2. Ensure that the extracted IoCs match the format (or part of it) found in AWS log records. For example, convert general terms like "AWS Golang SDK" to "aws-sdk-go/".
3. Avoid extracting duplications or redundant versions of the same IoC.
4. Be thorough and ensure that no IoC is missed.'''

# Respond in the following JSON format (if no IoCs are found, return an empty object - {}):
# {
#     "ip_addresses": ["..."], // Remove this key if no IP addresses are found
#     "user_agents": ["..."] // Remove this key if no user-agents are found
# }'''

# IOC_EXTRACTING_SYSTEM_PROMPT = """You are an advanced cybersecurity analysis tool specialized in extracting Indicators of Compromise (IoCs) from Cyber Threat Intelligence (CTI) texts. Your task is to analyze the provided CTI text and extract explicitly-mentioned, specific types of IoCs that are directly related to cloud environments logs: IP addresses and user-agents. Focus on the paragraph usually located at the end of the document under a corresponding heading, where IoCs are listed. Reformat any obfuscated IPs to their standard X.X.X.X format.
#
# Ensure you extract IoCs that are explicitly associated with the threat actor. Be thorough and ensure that no IoC is missed. If no IoCs are found, return an empty JSON object ({}).
#
# Respond in a JSON format, structured as follows:
# {
#     "ioc": {...}
# }"""


def generate_ioc_extracting_user_prompt(markdown: str) -> str:
    return f'''Extract the IoCs from the following CTI text.

CTI Text: """
{markdown}
"""'''
