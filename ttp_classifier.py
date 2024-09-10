import json
import logging
import os
import re
from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.ttp_classification_prompts import ttp_extracting_system_prompt, generate_ttp_extracting_user_prompt
from utils import validate_event


class TTPClassifier:
    tactic_id_to_name = {'TA0043': 'Reconnaissance', 'TA0042': 'Resource Development', 'TA0001': 'Initial Access',
                         'TA0002': 'Execution', 'TA0003': 'Persistence', 'TA0004': 'Privilege Escalation',
                         'TA0005': 'Defense Evasion', 'TA0006': 'Credential Access', 'TA0007': 'Discovery',
                         'TA0008': 'Lateral Movement', 'TA0009': 'Collection', 'TA0011': 'Command and Control',
                         'TA0010': 'Exfiltration', 'TA0040': 'Impact'}
    technique_name_to_id = {'Active Scanning': 'T1595', 'Gather Victim Host Information': 'T1592',
                            'Gather Victim Identity Information': 'T1589', 'Gather Victim Network Information': 'T1590',
                            'Gather Victim Org Information': 'T1591', 'Phishing for Information': 'T1598',
                            'Search Closed Sources': 'T1597', 'Search Open Technical Databases': 'T1596',
                            'Search Open Websites/Domains': 'T1593', 'Search Victim-Owned Websites': 'T1594',
                            'Acquire Access': 'T1650', 'Acquire Infrastructure': 'T1583',
                            'Compromise Accounts': 'T1586', 'Compromise Infrastructure': 'T1584',
                            'Develop Capabilities': 'T1587', 'Establish Accounts': 'T1585',
                            'Obtain Capabilities': 'T1588', 'Stage Capabilities': 'T1608', 'Content Injection': 'T1659',
                            'Drive-by Compromise': 'T1189', 'Exploit Public-Facing Application': 'T1190',
                            'External Remote Services': 'T1133', 'Hardware Additions': 'T1200', 'Phishing': 'T1566',
                            'Replication Through Removable Media': 'T1091', 'Supply Chain Compromise': 'T1195',
                            'Trusted Relationship': 'T1199', 'Valid Accounts': 'T1078',
                            'Cloud Administration Command': 'T1651', 'Command and Scripting Interpreter': 'T1059',
                            'Container Administration Command': 'T1609', 'Deploy Container': 'T1610',
                            'Exploitation for Client Execution': 'T1203', 'Inter-Process Communication': 'T1559',
                            'Native API': 'T1106', 'Scheduled Task/Job': 'T1053', 'Serverless Execution': 'T1648',
                            'Shared Modules': 'T1129', 'Software Deployment Tools': 'T1072', 'System Services': 'T1569',
                            'User Execution': 'T1204', 'Windows Management Instrumentation': 'T1047',
                            'Account Manipulation': 'T1098', 'BITS Jobs': 'T1197',
                            'Boot or Logon Autostart Execution': 'T1547',
                            'Boot or Logon Initialization Scripts': 'T1037', 'Browser Extensions': 'T1176',
                            'Compromise Client Software Binary': 'T1554', 'Create Account': 'T1136',
                            'Create or Modify System Process': 'T1543', 'Event Triggered Execution': 'T1546',
                            'Hijack Execution Flow': 'T1574', 'Implant Internal Image': 'T1525',
                            'Modify Authentication Process': 'T1556', 'Office Application Startup': 'T1137',
                            'Power Settings': 'T1653', 'Pre-OS Boot': 'T1542', 'Server Software Component': 'T1505',
                            'Traffic Signaling': 'T1205', 'Abuse Elevation Control Mechanism': 'T1548',
                            'Access Token Manipulation': 'T1134', 'Domain Policy Modification': 'T1484',
                            'Escape to Host': 'T1611', 'Exploitation for Privilege Escalation': 'T1068',
                            'Process Injection': 'T1055', 'Build Image on Host': 'T1612', 'Debugger Evasion': 'T1622',
                            'Deobfuscate/Decode Files or Information': 'T1140', 'Direct Volume Access': 'T1006',
                            'Execution Guardrails': 'T1480', 'Exploitation for Defense Evasion': 'T1211',
                            'File and Directory Permissions Modification': 'T1222', 'Hide Artifacts': 'T1564',
                            'Impair Defenses': 'T1562', 'Impersonation': 'T1656', 'Indicator Removal': 'T1070',
                            'Indirect Command Execution': 'T1202', 'Masquerading': 'T1036',
                            'Modify Cloud Compute Infrastructure': 'T1578', 'Modify Registry': 'T1112',
                            'Modify System Image': 'T1601', 'Network Boundary Bridging': 'T1599',
                            'Obfuscated Files or Information': 'T1027', 'Plist File Modification': 'T1647',
                            'Reflective Code Loading': 'T1620', 'Rogue Domain Controller': 'T1207', 'Rootkit': 'T1014',
                            'Subvert Trust Controls': 'T1553', 'System Binary Proxy Execution': 'T1218',
                            'System Script Proxy Execution': 'T1216', 'Template Injection': 'T1221',
                            'Trusted Developer Utilities Proxy Execution': 'T1127',
                            'Unused/Unsupported Cloud Regions': 'T1535',
                            'Use Alternate Authentication Material': 'T1550', 'Virtualization/Sandbox Evasion': 'T1497',
                            'Weaken Encryption': 'T1600', 'XSL Script Processing': 'T1220',
                            'Adversary-in-the-Middle': 'T1557', 'Brute Force': 'T1110',
                            'Credentials from Password Stores': 'T1555', 'Exploitation for Credential Access': 'T1212',
                            'Forced Authentication': 'T1187', 'Forge Web Credentials': 'T1606',
                            'Input Capture': 'T1056', 'Multi-Factor Authentication Interception': 'T1111',
                            'Multi-Factor Authentication Request Generation': 'T1621', 'Network Sniffing': 'T1040',
                            'OS Credential Dumping': 'T1003', 'Steal Application Access Token': 'T1528',
                            'Steal or Forge Authentication Certificates': 'T1649',
                            'Steal or Forge Kerberos Tickets': 'T1558', 'Steal Web Session Cookie': 'T1539',
                            'Unsecured Credentials': 'T1552', 'Account Discovery': 'T1087',
                            'Application Window Discovery': 'T1010', 'Browser Information Discovery': 'T1217',
                            'Cloud Infrastructure Discovery': 'T1580', 'Cloud Service Dashboard': 'T1538',
                            'Cloud Service Discovery': 'T1526', 'Cloud Storage Object Discovery': 'T1619',
                            'Container and Resource Discovery': 'T1613', 'Device Driver Discovery': 'T1652',
                            'Domain Trust Discovery': 'T1482', 'File and Directory Discovery': 'T1083',
                            'Group Policy Discovery': 'T1615', 'Log Enumeration': 'T1654',
                            'Network Service Discovery': 'T1046', 'Network Share Discovery': 'T1135',
                            'Password Policy Discovery': 'T1201', 'Peripheral Device Discovery': 'T1120',
                            'Permission Groups Discovery': 'T1069', 'Process Discovery': 'T1057',
                            'Query Registry': 'T1012', 'Remote System Discovery': 'T1018',
                            'Software Discovery': 'T1518', 'System Information Discovery': 'T1082',
                            'System Location Discovery': 'T1614', 'System Network Configuration Discovery': 'T1016',
                            'System Network Connections Discovery': 'T1049', 'System Owner/User Discovery': 'T1033',
                            'System Service Discovery': 'T1007', 'System Time Discovery': 'T1124',
                            'Exploitation of Remote Services': 'T1210', 'Internal Spearphishing': 'T1534',
                            'Lateral Tool Transfer': 'T1570', 'Remote Service Session Hijacking': 'T1563',
                            'Remote Services': 'T1021', 'Taint Shared Content': 'T1080',
                            'Archive Collected Data': 'T1560', 'Audio Capture': 'T1123',
                            'Automated Collection': 'T1119', 'Browser Session Hijacking': 'T1185',
                            'Clipboard Data': 'T1115', 'Data from Cloud Storage': 'T1530',
                            'Data from Configuration Repository': 'T1602',
                            'Data from Information Repositories': 'T1213', 'Data from Local System': 'T1005',
                            'Data from Network Shared Drive': 'T1039', 'Data from Removable Media': 'T1025',
                            'Data Staged': 'T1074', 'Email Collection': 'T1114', 'Screen Capture': 'T1113',
                            'Video Capture': 'T1125', 'Application Layer Protocol': 'T1071',
                            'Communication Through Removable Media': 'T1092', 'Data Encoding': 'T1132',
                            'Data Obfuscation': 'T1001', 'Dynamic Resolution': 'T1568', 'Encrypted Channel': 'T1573',
                            'Fallback Channels': 'T1008', 'Ingress Tool Transfer': 'T1105',
                            'Multi-Stage Channels': 'T1104', 'Non-Application Layer Protocol': 'T1095',
                            'Non-Standard Port': 'T1571', 'Protocol Tunneling': 'T1572', 'Proxy': 'T1090',
                            'Remote Access Software': 'T1219', 'Web Service': 'T1102',
                            'Automated Exfiltration': 'T1020', 'Data Transfer Size Limits': 'T1030',
                            'Exfiltration Over Alternative Protocol': 'T1048', 'Exfiltration Over C2 Channel': 'T1041',
                            'Exfiltration Over Other Network Medium': 'T1011',
                            'Exfiltration Over Physical Medium': 'T1052', 'Exfiltration Over Web Service': 'T1567',
                            'Scheduled Transfer': 'T1029', 'Transfer Data to Cloud Account': 'T1537',
                            'Account Access Removal': 'T1531', 'Data Destruction': 'T1485',
                            'Data Encrypted for Impact': 'T1486', 'Data Manipulation': 'T1565', 'Defacement': 'T1491',
                            'Disk Wipe': 'T1561', 'Endpoint Denial of Service': 'T1499', 'Financial Theft': 'T1657',
                            'Firmware Corruption': 'T1495', 'Inhibit System Recovery': 'T1490',
                            'Network Denial of Service': 'T1498', 'Resource Hijacking': 'T1496',
                            'Service Stop': 'T1489', 'System Shutdown/Reboot': 'T1529'}

    def __init__(self, model_name: str = 'chatgpt-4o-latest', api_key: str = None, temperature: float = 0.5):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature

    @staticmethod
    def _generate_ttp_classification_messages(event_to_source: dict[str, str], paragraph: str) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": ttp_extracting_system_prompt},
            {"role": "user", "content": generate_ttp_extracting_user_prompt(event_to_source, paragraph)}
        ]

    def _send_ttp_classification_request(self, messages: list[dict[str, str]]) -> ChatCompletion:
        return self.client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            messages=messages,
            response_format={"type": "json_object"}
        )

    @staticmethod
    def _reformat_event_to_ttps(event_to_ttps: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
        reformatted_event_to_ttps = {}
        for event, ttps in event_to_ttps.items():
            reformatted_event = validate_event(event)
            reformatted_event_to_ttps[reformatted_event] = {}
            for k, v in ttps.items():
                if v:
                    reformatted_event_to_ttps[event][k] = v

        return reformatted_event_to_ttps

    @staticmethod
    def _simplify_ttps(event_to_ttps: dict[str, dict[str, str]]) -> None:
        for event, ttps in event_to_ttps.items():
            if 'tactic_name' in ttps:
                tactic_name = ttps['tactic_name'].upper().replace('ATTACK.', '').replace("'", "")
                if re.match(r'^TA\d{4}$', tactic_name) and tactic_name in TTPClassifier.tactic_id_to_name:
                    tactic_name = TTPClassifier.tactic_id_to_name[tactic_name]
                ttps['tactic_name'] = f'attack.{tactic_name.lower().replace(" ", "_")}'
            if 'technique_id' in ttps:
                technique_id = ttps['technique_id'].title().replace('Attack.', '').replace("'", "").replace('_', ' ')
                if re.match(r'^.*\..*$', technique_id):
                    technique_id = technique_id.split('.')[-1]
                if not re.match(r'^T\d{4}$', technique_id) and technique_id in TTPClassifier.technique_name_to_id:
                    technique_id = TTPClassifier.technique_name_to_id[technique_id]
                elif re.match(r'^[A-Za-z ]+\(T\d{4}\)$', technique_id):
                    technique_id = technique_id.split('(')[-1].split(')')[0]
                ttps['technique_id'] = f'attack.{technique_id.lower()}'
            if 'subtechnique_id' in ttps:
                subtechnique_id = ttps['subtechnique_id'].title().replace('Attack.', '').replace("'", "").replace('_', ' ')
                if re.match(r'^.*\..*\..*$', subtechnique_id):
                    subtechnique_id = subtechnique_id.split('.')[-2] + '.' + subtechnique_id.split('.')[-1]
                if re.match(r'^\d{3}$', subtechnique_id):
                    ttps['subtechnique_id'] = f'{ttps["technique_id"]}.{subtechnique_id}'
                else:
                    if re.match(r'^[A-Za-z :]+\(T\d{4}\.\d{3}\)$', subtechnique_id):
                        subtechnique_id = subtechnique_id.split('(')[-1].split(')')[0]
                    ttps['subtechnique_id'] = f'attack.{subtechnique_id.lower()}'

    def classify_api_call_ttp(self, event_to_source: dict[str, str], paragraph: str) -> dict[str, dict[str, str]] | None:
        messages = TTPClassifier._generate_ttp_classification_messages(event_to_source, paragraph)

        try:
            response = self._send_ttp_classification_request(messages)
        except Exception as e:
            logging.error(f"Error extracting TTPs: {e}")
            return None

        response = response.choices[0].message.content
        event_to_ttps = json.loads(response)
        event_to_ttps = TTPClassifier._reformat_event_to_ttps(event_to_ttps)
        # TTPClassifier._simplify_ttps(event_to_ttps)

        return event_to_ttps
