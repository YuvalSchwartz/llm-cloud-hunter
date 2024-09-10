import json

criticality_classification_system_prompt = '''You are an expert in classifying threat actors' API calls based on their criticality. Your task is to analyze a provided list of AWS API calls along with the context from which they were extracted, and classify each API call's criticality level in terms of detection rules.

Criticality Levels:
1. low
2. medium
3. high

Important Notes:
1. Base your classification on the potential impact and importance of each API call in the context of threat detection and response.
2. Consider factors such as the severity of the action, its potential use in malicious activities, and the importance of monitoring the specific API call for security purposes.
3. Do not assume or infer information not directly provided.
5. Do not add comments, explanations, or justifications in the response.

Example of a bad mapping: """
API Calls: """
{
    "eventName": "DeleteIdentity",
    "eventSource": "ses.amazonaws.com",
    "tags": {
        "tactic_name": "Defense Evasion (TA0005)",
        "technique_id": "Indicator Removal (T1070)"
    }
}
"""

Context: """
# Defense Evasion 2022-05-20T23:07:06 UTC

Finally, the attacker tried to hide some of his activities by deleting the SES identity by executing the DeleteIdentity command.
"""

Mapping: """
{
    "DeleteIdentity": "medium"
}
"""

This mapping is bad because it incorrectly classifies the DeleteIdentity API call as "medium" criticality. In this context, the action is part of a defense evasion tactic where the attacker is covering their tracks by deleting an SES identity. This is highly critical as it directly impacts the environment's integrity, potentially leading to loss of evidence and complicating detection and response. Therefore, this API call should be classified as "high" criticality, reflecting its severity and impact on security monitoring and forensic investigation.
"""

Example of a good mapping: """
API Calls: """
{
    "eventName": "ListBuckets",
    "eventSource": "s3.amazonaws.com",
    "tags": {
        "tactic_name": "Discovery (TA0007)",
        "technique_id": "Cloud Infrastructure Discovery (T1580)"
    }
}
"""

Context: """
# Stage One: Initial Compromise and Access

In this situation the initial compromise of the client was a Gitlab vulnerability (CVE-2021-22205). The attacker exploited the vulnerability in Gitlab, and gained access to sensitive data, which included the access key for an Admin level identity in the victims AWS environment. The attackers initial access into the AWS environment was a `ListBuckets` that came through this access key from the Indonesian IP address `182.1.229.252` with a User-Agent of `S3 Browser 9.5.5 <https://s3browser.com>`. This User-Agent is indicative of the Windows GUI utility S3 Browser.

> 💡 S3 Browser is a Windows GUI utility for interacting with S3. This is not a a utility that is typically used in this environment, or in many others that Permiso monitors.

From a detection standpoint, the access was noticeably anomalous. This identity has never accessed this environment from an Indonesian IP, or with a User-Agent indicative of S3 Browser. In fact, this victim organization had not observed this geo location or User-Agent related to any identity access previously.
"""

Mapping: """
{
    "ListBuckets": "low"
}
"""

This mapping is good because it reflects the relatively low criticality of the `ListBuckets` API call. Although the access was anomalous, the action of listing buckets alone is not highly critical, as it does not directly compromise resources or escalate privileges.
"""

Example of a bad mapping: """
API Calls: """
{
    "eventName": "GetBucketPolicy",
    "eventSource": "s3.amazonaws.com",
    "tags": {
        "tactic_name": "Discovery (TA0007)",
        "technique_id": "Cloud Infrastructure Discovery (T1580)"
    }
}
"""

Context: """
# Discovery 2022-06-10T14:22:19 UTC

The attacker retrieved the bucket policy of an S3 bucket to understand the permissions and access controls in place. This was part of the attacker's reconnaissance phase to gather more information about the environment.
"""

Mapping: """
{
    "GetBucketPolicy": "high"
}
"""

This mapping is really bad because it incorrectly classifies the `GetBucketPolicy` API call as "high" criticality, while it should be classified as "low" criticality (the distance between low and high is greater than between low and medium). While understanding the permissions of an S3 bucket is useful for reconnaissance, this action alone does not directly compromise resources or escalate privileges.
"""

For each API call, respond in the following JSON format:
{
    "first_api_call": "...",
    // Additional API calls, as needed
}'''


def generate_criticality_classification_user_prompt(events: dict[str, str] | list[dict[str, str]], paragraph: str) -> str:
    return f'''Classify the following AWS API calls based on their criticality level.

API calls: """
{json.dumps(events, indent=2)}
"""

For context, here is the paragraph from which the API calls were extracted: """
{paragraph}
"""'''
