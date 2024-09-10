cloud_tactic_name_to_technique_names = {'Initial Access': ['Drive-by Compromise', 'Exploit Public-Facing Application', 'Phishing', 'Trusted Relationship', 'Valid Accounts'], 'Execution': ['Cloud Administration Command', 'Command and Scripting Interpreter', 'Serverless Execution', 'Software Deployment Tools', 'User Execution'], 'Persistence': ['Account Manipulation', 'Create Account', 'Event Triggered Execution', 'Implant Internal Image', 'Modify Authentication Process', 'Office Application Startup', 'Valid Accounts'], 'Privilege Escalation': ['Abuse Elevation Control Mechanism', 'Account Manipulation', 'Domain or Tenant Policy Modification', 'Event Triggered Execution', 'Valid Accounts'], 'Defense Evasion': ['Abuse Elevation Control Mechanism', 'Domain or Tenant Policy Modification', 'Exploitation for Defense Evasion', 'Hide Artifacts', 'Impair Defenses', 'Impersonation', 'Indicator Removal', 'Modify Authentication Process', 'Modify Cloud Compute Infrastructure', 'Unused/Unsupported Cloud Regions', 'Use Alternate Authentication Material', 'Valid Accounts'], 'Credential Access': ['Brute Force', 'Credentials from Password Stores', 'Exploitation for Credential Access', 'Forge Web Credentials', 'Modify Authentication Process', 'Multi-Factor Authentication Request Generation', 'Network Sniffing', 'Steal Application Access Token', 'Steal or Forge Authentication Certificates', 'Steal Web Session Cookie', 'Unsecured Credentials'], 'Discovery': ['Account Discovery', 'Cloud Infrastructure Discovery', 'Cloud Service Dashboard', 'Cloud Service Discovery', 'Cloud Storage Object Discovery', 'Log Enumeration', 'Network Service Discovery', 'Network Sniffing', 'Password Policy Discovery', 'Permission Groups Discovery', 'Software Discovery', 'System Information Discovery', 'System Location Discovery', 'System Network Connections Discovery'], 'Lateral Movement': ['Internal Spearphishing', 'Remote Services', 'Software Deployment Tools', 'Taint Shared Content', 'Use Alternate Authentication Material'], 'Collection': ['Automated Collection', 'Data from Cloud Storage', 'Data from Information Repositories', 'Data Staged', 'Email Collection'], 'Exfiltration': ['Exfiltration Over Alternative Protocol', 'Exfiltration Over Web Service', 'Transfer Data to Cloud Account'], 'Impact': ['Account Access Removal', 'Data Destruction', 'Data Encrypted for Impact', 'Defacement', 'Endpoint Denial of Service', 'Financial Theft', 'Inhibit System Recovery', 'Network Denial of Service', 'Resource Hijacking']}
cloud_technique_name_to_id = {'Drive-by Compromise': 'T1189', 'Exploit Public-Facing Application': 'T1190', 'Phishing': 'T1566', 'Trusted Relationship': 'T1199', 'Valid Accounts': 'T1078', 'Cloud Administration Command': 'T1651', 'Command and Scripting Interpreter': 'T1059', 'Serverless Execution': 'T1648', 'Software Deployment Tools': 'T1072', 'User Execution': 'T1204', 'Account Manipulation': 'T1098', 'Create Account': 'T1136', 'Event Triggered Execution': 'T1546', 'Implant Internal Image': 'T1525', 'Modify Authentication Process': 'T1556', 'Office Application Startup': 'T1137', 'Abuse Elevation Control Mechanism': 'T1548', 'Domain or Tenant Policy Modification': 'T1484', 'Exploitation for Defense Evasion': 'T1211', 'Hide Artifacts': 'T1564', 'Impair Defenses': 'T1562', 'Impersonation': 'T1656', 'Indicator Removal': 'T1070', 'Modify Cloud Compute Infrastructure': 'T1578', 'Modify Registry': 'T1112', 'Unused/Unsupported Cloud Regions': 'T1535', 'Use Alternate Authentication Material': 'T1550', 'Brute Force': 'T1110', 'Credentials from Password Stores': 'T1555', 'Exploitation for Credential Access': 'T1212', 'Forge Web Credentials': 'T1606', 'Multi-Factor Authentication Request Generation': 'T1621', 'Network Sniffing': 'T1040', 'Steal Application Access Token': 'T1528', 'Steal or Forge Authentication Certificates': 'T1649', 'Steal Web Session Cookie': 'T1539', 'Unsecured Credentials': 'T1552', 'Account Discovery': 'T1087', 'Cloud Infrastructure Discovery': 'T1580', 'Cloud Service Dashboard': 'T1538', 'Cloud Service Discovery': 'T1526', 'Cloud Storage Object Discovery': 'T1619', 'Log Enumeration': 'T1654', 'Network Service Discovery': 'T1046', 'Password Policy Discovery': 'T1201', 'Permission Groups Discovery': 'T1069', 'Software Discovery': 'T1518', 'System Information Discovery': 'T1082', 'System Location Discovery': 'T1614', 'System Network Connections Discovery': 'T1049', 'Internal Spearphishing': 'T1534', 'Remote Services': 'T1021', 'Taint Shared Content': 'T1080', 'Automated Collection': 'T1119', 'Data from Cloud Storage': 'T1530', 'Data from Information Repositories': 'T1213', 'Data Staged': 'T1074', 'Email Collection': 'T1114', 'Exfiltration Over Alternative Protocol': 'T1048', 'Exfiltration Over Web Service': 'T1567', 'Transfer Data to Cloud Account': 'T1537', 'Account Access Removal': 'T1531', 'Data Destruction': 'T1485', 'Data Encrypted for Impact': 'T1486', 'Defacement': 'T1491', 'Endpoint Denial of Service': 'T1499', 'Financial Theft': 'T1657', 'Inhibit System Recovery': 'T1490', 'Network Denial of Service': 'T1498', 'Resource Hijacking': 'T1496'}
cloud_technique_name_to_subtechnique_name_to_id = {'Phishing': {'Spearphishing Attachment': '001', 'Spearphishing Link': '002', 'Spearphishing via Service': '003', 'Spearphishing Voice': '004'}, 'Valid Accounts': {'Default Accounts': '001', 'Domain Accounts': '002', 'Local Accounts': '003', 'Cloud Accounts': '004'}, 'Command and Scripting Interpreter': {'PowerShell': '001', 'AppleScript': '002', 'Windows Command Shell': '003', 'Unix Shell': '004', 'Visual Basic': '005', 'Python': '006', 'JavaScript': '007', 'Network Device CLI': '008', 'Cloud API': '009'}, 'User Execution': {'Malicious Link': '001', 'Malicious File': '002', 'Malicious Image': '003'}, 'Account Manipulation': {'Additional Cloud Credentials': '001', 'Additional Email Delegate Permissions': '002', 'Additional Cloud Roles': '003', 'SSH Authorized Keys': '004', 'Device Registration': '005', 'Additional Container Cluster Roles': '006'}, 'Create Account': {'Local Account': '001', 'Domain Account': '002', 'Cloud Account': '003'}, 'Modify Authentication Process': {'Domain Controller Authentication': '001', 'Password Filter DLL': '002', 'Pluggable Authentication Modules': '003', 'Network Device Authentication': '004', 'Reversible Encryption': '005', 'Multi-Factor Authentication': '006', 'Hybrid Identity': '007', 'Network Provider DLL': '008'}, 'Office Application Startup': {'Office Template Macros': '001', 'Office Test': '002', 'Outlook Forms': '003', 'Outlook Home Page': '004', 'Outlook Rules': '005', 'Add-ins': '006'}, 'Abuse Elevation Control Mechanism': {'Setuid and Setgid': '001', 'Bypass User Account Control': '002', 'Sudo and Sudo Caching': '003', 'Elevated Execution with Prompt': '004', 'Temporary Elevated Cloud Access': '005'}, 'Domain Policy Modification': {'Group Policy Modification': '001', 'Domain Trust Modification': '002'}, 'Hide Artifacts': {'Hidden Files and Directories': '001', 'Hidden Users': '002', 'Hidden Window': '003', 'NTFS File Attributes': '004', 'Hidden File System': '005', 'Run Virtual Instance': '006', 'VBA Stomping': '007', 'Email Hiding Rules': '008', 'Resource Forking': '009', 'Process Argument Spoofing': '010', 'Ignore Process Interrupts': '011'}, 'Impair Defenses': {'Disable or Modify Tools': '001', 'Disable Windows Event Logging': '002', 'Impair Command History Logging': '003', 'Disable or Modify System Firewall': '004', 'Indicator Blocking': '005', 'Disable or Modify Cloud Firewall': '006', 'Disable or Modify Cloud Logs': '007', 'Safe Mode Boot': '008', 'Downgrade Attack': '009', 'Spoof Security Alerting': '010', 'Disable or Modify Linux Audit System': '011'}, 'Indicator Removal': {'Clear Windows Event Logs': '001', 'Clear Linux or Mac System Logs': '002', 'Clear Command History': '003', 'File Deletion': '004', 'Network Share Connection Removal': '005', 'Timestomp': '006', 'Clear Network Connection History and Configurations': '007', 'Clear Mailbox Data': '008', 'Clear Persistence': '009'}, 'Modify Cloud Compute Infrastructure': {'Create Snapshot': '001', 'Create Cloud Instance': '002', 'Delete Cloud Instance': '003', 'Revert Cloud Instance': '004', 'Modify Cloud Compute Configurations': '005'}, 'Use Alternate Authentication Material': {'Application Access Token': '001', 'Pass the Hash': '002', 'Pass the Ticket': '003', 'Web Session Cookie': '004'}, 'Brute Force': {'Password Guessing': '001', 'Password Cracking': '002', 'Password Spraying': '003', 'Credential Stuffing': '004'}, 'Credentials from Password Stores': {'Keychain': '001', 'Securityd Memory': '002', 'Credentials from Web Browsers': '003', 'Windows Credential Manager': '004', 'Password Managers': '005', 'Cloud Secrets Management Stores': '006'}, 'Forge Web Credentials': {'Web Cookies': '001', 'SAML Tokens': '002'}, 'Unsecured Credentials': {'Credentials In Files': '001', 'Credentials in Registry': '002', 'Bash History': '003', 'Private Keys': '004', 'Cloud Instance Metadata API': '005', 'Group Policy Preferences': '006', 'Container API': '007', 'Chat Messages': '008'}, 'Account Discovery': {'Local Account': '001', 'Domain Account': '002', 'Email Account': '003', 'Cloud Account': '004'}, 'Permission Groups Discovery': {'Local Groups': '001', 'Domain Groups': '002', 'Cloud Groups': '003'}, 'Software Discovery': {'Security Software Discovery': '001'}, 'Remote Services': {'Remote Desktop Protocol': '001', 'SMB/Windows Admin Shares': '002', 'Distributed Component Object Model': '003', 'SSH': '004', 'VNC': '005', 'Windows Remote Management': '006', 'Cloud Services': '007', 'Direct Cloud VM Connections': '008'}, 'Data from Information Repositories': {'Confluence': '001', 'Sharepoint': '002', 'Code Repositories': '003'}, 'Data Staged': {'Local Data Staging': '001', 'Remote Data Staging': '002'}, 'Email Collection': {'Local Email Collection': '001', 'Remote Email Collection': '002', 'Email Forwarding Rule': '003'}, 'Exfiltration Over Web Service': {'Exfiltration to Code Repository': '001', 'Exfiltration to Cloud Storage': '002', 'Exfiltration to Text Storage Sites': '003', 'Exfiltration Over Webhook': '004'}, 'Defacement': {'Internal Defacement': '001', 'External Defacement': '002'}, 'Endpoint Denial of Service': {'OS Exhaustion Flood': '001', 'Service Exhaustion Flood': '002', 'Application Exhaustion Flood': '003', 'Application or System Exploitation': '004'}, 'Network Denial of Service': {'Direct Network Flood': '001', 'Reflection Amplification': '002'}}


ttp_extracting_system_prompt = f'''You are an expert in mapping threat actors' API calls to cloud-based MITRE ATT&CK TTPs. Given AWS API calls and the Cyber Threat Intelligence (CTI) text paragraph from which they were extracted, your task is to identify the most relevant cloud-based MITRE ATT&CK TTPs that best represent the threat actors’ actions depicted by the API calls, and assign appropriate cloud-based MITRE ATT&CK TTPs to each. Maintain a clear and concise mapping, avoiding overly broad or non-specific TTP assignments.

Important Notes:
1. Tactics should be assigned as names, and techniques and sub-techniques should be assigned as IDs (in Txxx and Txxx.xxx formats, respectively).
2. Use the provided CTI paragraph context to refine TTP assignments when it offers additional insights. If the context just repeats the API call, make your decisions based only on the API call itself.
3. Map techniques and sub-techniques only when you are highly confident in their relevance, as not every API call corresponds to a technique or sub-technique. If you are unsure, leave the field null.

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
        "tactic_name": "Discovery",
        "technique_id": "Cloud Infrastructure Discovery (T1580)",
        "subtechnique_id": null
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
        "tactic_name": "Defense Evasion",
        "technique_id": "Modify Cloud Compute Infrastructure (T1578)",
        "subtechnique_id": "Modify Cloud Compute Infrastructure: Create Cloud Instance (T1578.002)"
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
        "tactic_name": "Privilege Escalation (TA0004)",
        "technique_id": "Account Manipulation (T1098)",
        "subtechnique_id": "Account Manipulation: Additional Cloud Roles (T1098.003)"
    }},
    "UpdateLoginProfile": {{
        "tactic_name": "Privilege Escalation (TA0004)",
        "technique_id": "Account Manipulation (T1098)",
        "subtechnique_id": null
    }}
}}
"""

This mapping is good because it accurately reflects the specific actions and context described. The `ReplaceIamInstanceProfileAssociation` API call is correctly mapped to the "Account Manipulation" technique with the sub-technique "Additional Cloud Roles," as this API call involves modifying the role associated with an EC2 instance, which directly aligns with the manipulation of cloud roles to escalate privileges. The `UpdateLoginProfile` API call is mapped to the broader "Account Manipulation" technique without a sub-technique, as this action involves altering the login profile, which is a clear example of account manipulation but does not specifically fit under any of the available sub-techniques. The mapping distinguishes between the nuances and use cases of each API call.
"""

Refer to each API call separately. Respond in the following JSON format:
{{
    "first_api_call": {{
        "tactic_name": "...", // Mandatory
        "technique_id": "...", // Optional - put null if not applicable
        "subtechnique_id": "...", // Optional - put null if not applicable
    }},
    // Additional API calls and their TTP mappings, as needed
}}

Here are all the MITRE ATT&CK cloud-based TTPs. Ensure all mappings are drawn exclusively from these dictionaries and that each technique and sub-technique accurately aligns with the corresponding tactic: """
Tactic names to technique names: {cloud_tactic_name_to_technique_names}
Technique names to technique IDs: {cloud_technique_name_to_id}
Technique names to sub-technique names to IDs: {cloud_technique_name_to_subtechnique_name_to_id}
"""'''


def generate_ttp_extracting_user_prompt(event_to_source: dict[str, str], paragraph: str) -> str:
    return f'''Map each of the following AWS API calls to the relevant cloud-based MITRE ATT&CK TTPs.

API calls: """
{', '.join([f'{event} ({source})' for event, source in event_to_source.items()])}
"""

For context, here is the paragraph from which the API calls were extracted: """
{paragraph}
"""'''
