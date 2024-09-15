import json

tactic_to_techniques = {'Initial Access (TA0001)': ['Drive-by Compromise (T1189)', 'Exploit Public-Facing Application (T1190)', 'Phishing (T1566)', 'Trusted Relationship (T1199)', 'Valid Accounts (T1078)'], 'Execution (TA0002)': ['Cloud Administration Command (T1651)', 'Command and Scripting Interpreter (T1059)', 'Serverless Execution (T1648)', 'Software Deployment Tools (T1072)', 'User Execution (T1204)'], 'Persistence (TA0003)': ['Account Manipulation (T1098)', 'Create Account (T1136)', 'Event Triggered Execution (T1546)', 'Implant Internal Image (T1525)', 'Modify Authentication Process (T1556)', 'Office Application Startup (T1137)', 'Valid Accounts (T1078)'], 'Privilege Escalation (TA0004)': ['Abuse Elevation Control Mechanism (T1548)', 'Account Manipulation (T1098)', 'Domain or Tenant Policy Modification (T1484)', 'Event Triggered Execution (T1546)', 'Valid Accounts (T1078)'], 'Defense Evasion (TA0005)': ['Abuse Elevation Control Mechanism (T1548)', 'Domain or Tenant Policy Modification (T1484)', 'Exploitation for Defense Evasion (T1211)', 'Hide Artifacts (T1564)', 'Impair Defenses (T1562)', 'Impersonation (T1656)', 'Indicator Removal (T1070)', 'Modify Authentication Process (T1556)', 'Modify Cloud Compute Infrastructure (T1578)', 'Unused/Unsupported Cloud Regions (T1535)', 'Use Alternate Authentication Material (T1550)', 'Valid Accounts (T1078)'], 'Credential Access (TA0006)': ['Brute Force (T1110)', 'Credentials from Password Stores (T1555)', 'Exploitation for Credential Access (T1212)', 'Forge Web Credentials (T1606)', 'Modify Authentication Process (T1556)', 'Multi-Factor Authentication Request Generation (T1621)', 'Network Sniffing (T1040)', 'Steal Application Access Token (T1528)', 'Steal or Forge Authentication Certificates (T1649)', 'Steal Web Session Cookie (T1539)', 'Unsecured Credentials (T1552)'], 'Discovery (TA0007)': ['Account Discovery (T1087)', 'Cloud Infrastructure Discovery (T1580)', 'Cloud Service Dashboard (T1538)', 'Cloud Service Discovery (T1526)', 'Cloud Storage Object Discovery (T1619)', 'Log Enumeration (T1654)', 'Network Service Discovery (T1046)', 'Network Sniffing (T1040)', 'Password Policy Discovery (T1201)', 'Permission Groups Discovery (T1069)', 'Software Discovery (T1518)', 'System Information Discovery (T1082)', 'System Location Discovery (T1614)', 'System Network Connections Discovery (T1049)'], 'Lateral Movement (TA0008)': ['Internal Spearphishing (T1534)', 'Remote Services (T1021)', 'Software Deployment Tools (T1072)', 'Taint Shared Content (T1080)', 'Use Alternate Authentication Material (T1550)'], 'Collection (TA0009)': ['Automated Collection (T1119)', 'Data from Cloud Storage (T1530)', 'Data from Information Repositories (T1213)', 'Data Staged (T1074)', 'Email Collection (T1114)'], 'Exfiltration (TA0010)': ['Exfiltration Over Alternative Protocol (T1048)', 'Exfiltration Over Web Service (T1567)', 'Transfer Data to Cloud Account (T1537)'], 'Impact (TA0040)': ['Account Access Removal (T1531)', 'Data Destruction (T1485)', 'Data Encrypted for Impact (T1486)', 'Defacement (T1491)', 'Endpoint Denial of Service (T1499)', 'Financial Theft (T1657)', 'Inhibit System Recovery (T1490)', 'Network Denial of Service (T1498)', 'Resource Hijacking (T1496)']}
technique_to_subtechniques = {'Phishing (T1566)': ['Spearphishing Link (002)', 'Spearphishing Voice (004)'], 'Valid Accounts (T1078)': ['Default Accounts (001)', 'Cloud Accounts (004)'], 'Command and Scripting Interpreter (T1059)': ['Cloud API (009)'], 'User Execution (T1204)': ['Malicious Image (003)'], 'Account Manipulation (T1098)': ['Additional Cloud Credentials (001)', 'Additional Email Delegate Permissions (002)', 'Additional Cloud Roles (003)', 'SSH Authorized Keys (004)', 'Device Registration (005)'], 'Create Account (T1136)': ['Cloud Account (003)'], 'Modify Authentication Process (T1556)': ['Multi-Factor Authentication (006)', 'Hybrid Identity (007)', 'Conditional Access Policies (009)'], 'Office Application Startup (T1137)': ['Office Template Macros (001)', 'Office Test (002)', 'Outlook Forms (003)', 'Outlook Home Page (004)', 'Outlook Rules (005)', 'Add-ins (006)'], 'Abuse Elevation Control Mechanism (T1548)': ['Temporary Elevated Cloud Access (005)'], 'Domain or Tenant Policy Modification (T1484)': ['Trust Modification (002)'], 'Hide Artifacts (T1564)': ['Email Hiding Rules (008)'], 'Impair Defenses (T1562)': ['Disable or Modify Tools (001)', 'Disable or Modify Cloud Firewall (007)', 'Disable or Modify Cloud Logs (008)'], 'Indicator Removal (T1070)': ['Clear Mailbox Data (008)'], 'Modify Cloud Compute Infrastructure (T1578)': ['Create Snapshot (001)', 'Create Cloud Instance (002)', 'Delete Cloud Instance (003)', 'Revert Cloud Instance (004)', 'Modify Cloud Compute Configurations (005)'], 'Use Alternate Authentication Material (T1550)': ['Application Access Token (001)', 'Web Session Cookie (004)'], 'Brute Force (T1110)': ['Password Guessing (001)', 'Password Cracking (002)', 'Password Spraying (003)', 'Credential Stuffing (004)'], 'Credentials from Password Stores (T1555)': ['Cloud Secrets Management Stores (006)'], 'Forge Web Credentials (T1606)': ['Web Cookies (001)', 'SAML Tokens (002)'], 'Unsecured Credentials (T1552)': ['Credentials In Files (001)', 'Cloud Instance Metadata API (005)', 'Chat Messages (008)'], 'Account Discovery (T1087)': ['Email Account (003)', 'Cloud Account (004)'], 'Permission Groups Discovery (T1069)': ['Cloud Groups (003)'], 'Software Discovery (T1518)': ['Security Software Discovery (001)'], 'Remote Services (T1021)': ['Cloud Services (007)', 'Direct Cloud VM Connections (008)'], 'Data from Information Repositories (T1213)': ['Confluence (001)', 'Sharepoint (002)', 'Code Repositories (003)'], 'Data Staged (T1074)': ['Remote Data Staging (002)'], 'Email Collection (T1114)': ['Remote Email Collection (002)', 'Email Forwarding Rule (003)'], 'Exfiltration Over Web Service (T1567)': ['Exfiltration Over Webhook (004)'], 'Defacement (T1491)': ['External Defacement (002)'], 'Endpoint Denial of Service (T1499)': ['Service Exhaustion Flood (002)', 'Application Exhaustion Flood (003)', 'Application or System Exploitation (004)'], 'Network Denial of Service (T1498)': ['Direct Network Flood (001)', 'Reflection Amplification (002)']}

ttp_extracting_system_prompt = f'''You are an expert in mapping threat actors' API calls to cloud-based MITRE ATT&CK TTPs. Given AWS API calls and the Cyber Threat Intelligence (CTI) text paragraph from which they were extracted, your task is to identify the most relevant cloud-based MITRE ATT&CK TTPs that best represent the threat actors’ actions depicted by the API calls, and assign appropriate cloud-based MITRE ATT&CK TTPs to each. Maintain a clear and concise mapping, avoiding overly broad or non-specific TTP assignments.

Important Notes:
1. Use the provided CTI paragraph context to refine TTP assignments when it offers additional insights. If the context just repeats the API call, make your decisions based only on the API call itself.
2. Map techniques and sub-techniques only when you are highly confident in their relevance, as not every API call corresponds to a technique or sub-technique. If you are unsure, leave the field null/empty.

Example of a good mapping: """
API Calls: """
ListBuckets (s3.amazonaws.com)
"""

Context: """
# Stage One: Initial Compromise and Access

In this situation the initial compromise of the client was a Gitlab vulnerability (CVE-2021-22205). The attacker exploited the vulnerability in Gitlab, and gained access to sensitive data, which included the access key for an Admin level identity in the victims AWS environment. The attackers initial access into the AWS environment was a ListBuckets that came through this access key from the Indonesian IP address 182.1.229.252 with a User-Agent of S3 Browser 9.5.5 <https://s3browser.com> . This User-Agent is indicative of the Windows GUI utility S3 Browser.
From a detection standpoint, the access was noticeably anomalous. This identity has never accessed this environment from an Indonesian IP, or with a User-Agent indicative of S3 Browser. In fact, this victim organization had not observed this geo location or User-Agent related to any identity access previously.
"""

Mapping: """
{{
    "ListBuckets": {{
        "tactic": "Discovery",
        "technique": "Cloud Infrastructure Discovery (T1580)",
        "subtechnique": null
    }}
}}
"""

This mapping is good because despite the initial context suggesting an 'Initial Access' scenario, it effectively distinguishes the actual action of the API call from the broader narrative of the attack, ensuring an accurate and focused mapping. It correctly identifies the API call 'ListBuckets' as a Discovery tactic, specifically Cloud Infrastructure Discovery (T1580), because the API call directly involves exploring and identifying cloud storage resources, which is central to understanding the cloud infrastructure's layout and contents.
"""

Example of a bad mapping: """
API Calls: """
RunInstances (ec2.amazonaws.com)
"""

Context: """
About thirty-one (31) minutes after initial access, the attacker began to use the AWS web console to create EC2 instances for the purpose of crypto mining.
The attacker attempted to spin-up dozens of xlarge EC2 instances across many regions, but ran into resource limitations along the way:
We currently do not have sufficient p3.16xlarge capacity in zones with support for 'gp2' volumes. Our system will be working on provisioning additional capacity.
In total the attacker successfully created thirteen (13) ec2 instances in five (5) different regions. All Instances had the following attributes:
• Sized xlarge
• Had detailed cloudwatch monitoring disabled "monitoring": {{"state": "disabled"}}
• TCP/22 open to 0.0.0.0 (everyone)
• IPv4 enabled, IPv6 disabled
• HttpTokens set to optional
• Xen hypervisor
"""

Mapping: """
{{
    "RunInstances": {{
        "tactic": "Defense Evasion",
        "technique": "Modify Cloud Compute Infrastructure (T1578)",
        "subtechnique": "Modify Cloud Compute Infrastructure: Create Cloud Instance (T1578.002)"
    }}
}}
"""

This mapping is bad because although these TTPs could be relevant in scenarios where creating instances is used to evade detection or maintain persistence, the context here explicitly describes the creation of EC2 instances for the purpose of crypto mining. This action aligns more closely with the Impact tactic, specifically Resource Hijacking (T1496), as it directly pertains to the unauthorized use of resources for financial gain, rather than evading defenses.
"""

Example of a good mapping: """
API Calls: """
ReplaceIamInstanceProfileAssociation (ec2.amazonaws.com), UpdateLoginProfile (iam.amazonaws.com)
"""

Context: """
# Privilege Escalation (PE)

LUCR-3 often chooses initial victims who have the type of access necessary to carry out their mission. They do not always need to utilize privilege escalation techniques, but we have observed them do so on occasion in AWS environments.
LUCR-3 has utilized three (3) main techniques for privilege escalation in AWS:

1. Policy manipulation: LUCR-3 has been seen modifying the policy of existing roles assigned to EC2 instances (`ReplaceIamInstanceProfileAssociation`) as well as creating new ones with a full open policy.
2. `UpdateLoginProfile`: LUCR-3 will update the login profile and on occasion create one if it doesn’t exist to assign a password to an identity, so they can leverage for AWS Management Console logons.
3. SecretsManager Harvesting: Many organizations store credentials in SecretsManger or Terraform Vault for programmatic access from their cloud infrastructure. LUCR-3 will leverage AWS CloudShell to scrape all credentials that are available in SecretsManager and similar solutions.
"""

Mapping: """
{{
    "ReplaceIamInstanceProfileAssociation": {{
        "tactic": "Privilege Escalation (TA0004)",
        "technique": "Account Manipulation (T1098)",
        "subtechnique": "Account Manipulation: Additional Cloud Roles (T1098.003)"
    }},
    "UpdateLoginProfile": {{
        "tactic": "Privilege Escalation (TA0004)",
        "technique": "Account Manipulation (T1098)",
        "subtechnique": null
    }}
}}
"""

This mapping is good because it accurately reflects the specific actions and context described. The `ReplaceIamInstanceProfileAssociation` API call is correctly mapped to the "Account Manipulation" technique with the sub-technique "Additional Cloud Roles," as this API call involves modifying the role associated with an EC2 instance, which directly aligns with the manipulation of cloud roles to escalate privileges. The `UpdateLoginProfile` API call is mapped to the broader "Account Manipulation" technique without a sub-technique, as this action involves altering the login profile, which is a clear example of account manipulation but does not specifically fit under any of the available sub-techniques. The mapping distinguishes between the nuances and use cases of each API call.
"""

Refer to each API call separately. Respond in the following JSON format:
{{
    "first_api_call": {{
        "tactic": "...", // Mandatory
        "technique": "...", // Optional - put null if not applicable
        "subtechnique": "...", // Optional - put null if not applicable
    }},
    // Additional API calls and their TTP mappings, as needed
}}

Here are all the MITRE ATT&CK cloud-based TTPs. Ensure all mappings are drawn exclusively from these dictionaries and that each technique and sub-technique accurately aligns with the corresponding tactic:
Tactic to techniques:
{json.dumps(tactic_to_techniques, indent=2)}

Technique to sub-techniques:
{json.dumps(technique_to_subtechniques, indent=2)}'''


def generate_ttp_extracting_user_prompt(event_to_source: dict[str, str], paragraph: str) -> str:
    return f'''Map each of the following AWS API calls to the relevant cloud-based MITRE ATT&CK TTPs.

API calls: """
{', '.join([f'{event} ({source})' for event, source in event_to_source.items()])}
"""

For context, here is the paragraph from which the API calls were extracted: """
{paragraph}
"""'''
