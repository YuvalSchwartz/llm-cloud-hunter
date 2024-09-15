import logging
import os
import re
from datetime import datetime
import yaml
from pyparsing import Word, alphas, infixNotation, opAssoc, ParseResults


tactic_name_to_id = {'Initial Access': 'TA0001', 'Execution': 'TA0002', 'Persistence': 'TA0003', 'Privilege Escalation': 'TA0004', 'Defense Evasion': 'TA0005', 'Credential Access': 'TA0006', 'Discovery': 'TA0007', 'Lateral Movement': 'TA0008', 'Collection': 'TA0009', 'Exfiltration': 'TA0010', 'Impact': 'TA0040'}
technique_name_to_id = {'Drive-by Compromise': 'T1189', 'Exploit Public-Facing Application': 'T1190', 'Phishing': 'T1566', 'Trusted Relationship': 'T1199', 'Valid Accounts': 'T1078', 'Cloud Administration Command': 'T1651', 'Command and Scripting Interpreter': 'T1059', 'Serverless Execution': 'T1648', 'Software Deployment Tools': 'T1072', 'User Execution': 'T1204', 'Account Manipulation': 'T1098', 'Create Account': 'T1136', 'Event Triggered Execution': 'T1546', 'Implant Internal Image': 'T1525', 'Modify Authentication Process': 'T1556', 'Office Application Startup': 'T1137', 'Abuse Elevation Control Mechanism': 'T1548', 'Domain or Tenant Policy Modification': 'T1484', 'Exploitation for Defense Evasion': 'T1211', 'Hide Artifacts': 'T1564', 'Impair Defenses': 'T1562', 'Impersonation': 'T1656', 'Indicator Removal': 'T1070', 'Modify Cloud Compute Infrastructure': 'T1578', 'Modify Registry': 'T1112', 'Unused/Unsupported Cloud Regions': 'T1535', 'Use Alternate Authentication Material': 'T1550', 'Brute Force': 'T1110', 'Credentials from Password Stores': 'T1555', 'Exploitation for Credential Access': 'T1212', 'Forge Web Credentials': 'T1606', 'Multi-Factor Authentication Request Generation': 'T1621', 'Network Sniffing': 'T1040', 'Steal Application Access Token': 'T1528', 'Steal or Forge Authentication Certificates': 'T1649', 'Steal Web Session Cookie': 'T1539', 'Unsecured Credentials': 'T1552', 'Account Discovery': 'T1087', 'Cloud Infrastructure Discovery': 'T1580', 'Cloud Service Dashboard': 'T1538', 'Cloud Service Discovery': 'T1526', 'Cloud Storage Object Discovery': 'T1619', 'Log Enumeration': 'T1654', 'Network Service Discovery': 'T1046', 'Password Policy Discovery': 'T1201', 'Permission Groups Discovery': 'T1069', 'Software Discovery': 'T1518', 'System Information Discovery': 'T1082', 'System Location Discovery': 'T1614', 'System Network Connections Discovery': 'T1049', 'Internal Spearphishing': 'T1534', 'Remote Services': 'T1021', 'Taint Shared Content': 'T1080', 'Automated Collection': 'T1119', 'Data from Cloud Storage': 'T1530', 'Data from Information Repositories': 'T1213', 'Data Staged': 'T1074', 'Email Collection': 'T1114', 'Exfiltration Over Alternative Protocol': 'T1048', 'Exfiltration Over Web Service': 'T1567', 'Transfer Data to Cloud Account': 'T1537', 'Account Access Removal': 'T1531', 'Data Destruction': 'T1485', 'Data Encrypted for Impact': 'T1486', 'Defacement': 'T1491', 'Endpoint Denial of Service': 'T1499', 'Financial Theft': 'T1657', 'Inhibit System Recovery': 'T1490', 'Network Denial of Service': 'T1498', 'Resource Hijacking': 'T1496'}
technique_faulty_name_to_correct_name = {'Drive By Compromise': 'Drive-by Compromise', 'Exploit Public Facing Application': 'Exploit Public-Facing Application', 'Command And Scripting Interpreter': 'Command and Scripting Interpreter', 'Domain Or Tenant Policy Modification': 'Domain or Tenant Policy Modification', 'Exploitation For Defense Evasion': 'Exploitation for Defense Evasion', 'Credentials From Password Stores': 'Credentials from Password Stores', 'Exploitation For Credential Access': 'Exploitation for Credential Access', 'Multi Factor Authentication Request Generation': 'Multi-Factor Authentication Request Generation', 'Steal Or Forge Authentication Certificates': 'Steal or Forge Authentication Certificates', 'Data From Cloud Storage': 'Data from Cloud Storage', 'Data From Information Repositories': 'Data from Information Repositories', 'Transfer Data To Cloud Account': 'Transfer Data to Cloud Account', 'Data Encrypted For Impact': 'Data Encrypted for Impact', 'Endpoint Denial Of Service': 'Endpoint Denial of Service', 'Network Denial Of Service': 'Network Denial of Service'}
technique_id_to_name = {'T1189': 'Drive-by Compromise', 'T1190': 'Exploit Public-Facing Application', 'T1566': 'Phishing', 'T1199': 'Trusted Relationship', 'T1078': 'Valid Accounts', 'T1651': 'Cloud Administration Command', 'T1059': 'Command and Scripting Interpreter', 'T1648': 'Serverless Execution', 'T1072': 'Software Deployment Tools', 'T1204': 'User Execution', 'T1098': 'Account Manipulation', 'T1136': 'Create Account', 'T1546': 'Event Triggered Execution', 'T1525': 'Implant Internal Image', 'T1556': 'Modify Authentication Process', 'T1137': 'Office Application Startup', 'T1548': 'Abuse Elevation Control Mechanism', 'T1484': 'Domain or Tenant Policy Modification', 'T1211': 'Exploitation for Defense Evasion', 'T1564': 'Hide Artifacts', 'T1562': 'Impair Defenses', 'T1656': 'Impersonation', 'T1070': 'Indicator Removal', 'T1578': 'Modify Cloud Compute Infrastructure', 'T1112': 'Modify Registry', 'T1535': 'Unused/Unsupported Cloud Regions', 'T1550': 'Use Alternate Authentication Material', 'T1110': 'Brute Force', 'T1555': 'Credentials from Password Stores', 'T1212': 'Exploitation for Credential Access', 'T1606': 'Forge Web Credentials', 'T1621': 'Multi-Factor Authentication Request Generation', 'T1040': 'Network Sniffing', 'T1528': 'Steal Application Access Token', 'T1649': 'Steal or Forge Authentication Certificates', 'T1539': 'Steal Web Session Cookie', 'T1552': 'Unsecured Credentials', 'T1087': 'Account Discovery', 'T1580': 'Cloud Infrastructure Discovery', 'T1538': 'Cloud Service Dashboard', 'T1526': 'Cloud Service Discovery', 'T1619': 'Cloud Storage Object Discovery', 'T1654': 'Log Enumeration', 'T1046': 'Network Service Discovery', 'T1201': 'Password Policy Discovery', 'T1069': 'Permission Groups Discovery', 'T1518': 'Software Discovery', 'T1082': 'System Information Discovery', 'T1614': 'System Location Discovery', 'T1049': 'System Network Connections Discovery', 'T1534': 'Internal Spearphishing', 'T1021': 'Remote Services', 'T1080': 'Taint Shared Content', 'T1119': 'Automated Collection', 'T1530': 'Data from Cloud Storage', 'T1213': 'Data from Information Repositories', 'T1074': 'Data Staged', 'T1114': 'Email Collection', 'T1048': 'Exfiltration Over Alternative Protocol', 'T1567': 'Exfiltration Over Web Service', 'T1537': 'Transfer Data to Cloud Account', 'T1531': 'Account Access Removal', 'T1485': 'Data Destruction', 'T1486': 'Data Encrypted for Impact', 'T1491': 'Defacement', 'T1499': 'Endpoint Denial of Service', 'T1657': 'Financial Theft', 'T1490': 'Inhibit System Recovery', 'T1498': 'Network Denial of Service', 'T1496': 'Resource Hijacking'}
technique_id_to_subtechnique_id_to_name = {'T1566': {'002': 'Spearphishing Link', '004': 'Spearphishing Voice'}, 'T1078': {'001': 'Default Accounts', '004': 'Cloud Accounts'}, 'T1059': {'009': 'Cloud API'}, 'T1204': {'003': 'Malicious Image'}, 'T1098': {'001': 'Additional Cloud Credentials', '002': 'Additional Email Delegate Permissions', '003': 'Additional Cloud Roles', '004': 'SSH Authorized Keys', '005': 'Device Registration'}, 'T1136': {'003': 'Cloud Account'}, 'T1556': {'006': 'Multi-Factor Authentication', '007': 'Hybrid Identity', '009': 'Conditional Access Policies'}, 'T1137': {'001': 'Office Template Macros', '002': 'Office Test', '003': 'Outlook Forms', '004': 'Outlook Home Page', '005': 'Outlook Rules', '006': 'Add-ins'}, 'T1548': {'005': 'Temporary Elevated Cloud Access'}, 'T1484': {'002': 'Trust Modification'}, 'T1564': {'008': 'Email Hiding Rules'}, 'T1562': {'001': 'Disable or Modify Tools', '007': 'Disable or Modify Cloud Firewall', '008': 'Disable or Modify Cloud Logs'}, 'T1070': {'008': 'Clear Mailbox Data'}, 'T1578': {'001': 'Create Snapshot', '002': 'Create Cloud Instance', '003': 'Delete Cloud Instance', '004': 'Revert Cloud Instance', '005': 'Modify Cloud Compute Configurations'}, 'T1550': {'001': 'Application Access Token', '004': 'Web Session Cookie'}, 'T1110': {'001': 'Password Guessing', '002': 'Password Cracking', '003': 'Password Spraying', '004': 'Credential Stuffing'}, 'T1555': {'006': 'Cloud Secrets Management Stores'}, 'T1606': {'001': 'Web Cookies', '002': 'SAML Tokens'}, 'T1552': {'001': 'Credentials In Files', '005': 'Cloud Instance Metadata API', '008': 'Chat Messages'}, 'T1087': {'003': 'Email Account', '004': 'Cloud Account'}, 'T1069': {'003': 'Cloud Groups'}, 'T1518': {'001': 'Security Software Discovery'}, 'T1021': {'007': 'Cloud Services', '008': 'Direct Cloud VM Connections'}, 'T1213': {'001': 'Confluence', '002': 'Sharepoint', '003': 'Code Repositories'}, 'T1074': {'002': 'Remote Data Staging'}, 'T1114': {'002': 'Remote Email Collection', '003': 'Email Forwarding Rule'}, 'T1567': {'004': 'Exfiltration Over Webhook'}, 'T1491': {'002': 'External Defacement'}, 'T1499': {'002': 'Service Exhaustion Flood', '003': 'Application Exhaustion Flood', '004': 'Application or System Exploitation'}, 'T1498': {'001': 'Direct Network Flood', '002': 'Reflection Amplification'}}
technique_name_to_subtechnique_name_to_id = {'Phishing': {'Spearphishing Link': '002', 'Spearphishing Voice': '004'}, 'Valid Accounts': {'Default Accounts': '001', 'Cloud Accounts': '004'}, 'Command and Scripting Interpreter': {'Cloud API': '009'}, 'User Execution': {'Malicious Image': '003'}, 'Account Manipulation': {'Additional Cloud Credentials': '001', 'Additional Email Delegate Permissions': '002', 'Additional Cloud Roles': '003', 'SSH Authorized Keys': '004', 'Device Registration': '005'}, 'Create Account': {'Cloud Account': '003'}, 'Modify Authentication Process': {'Multi-Factor Authentication': '006', 'Hybrid Identity': '007', 'Conditional Access Policies': '009'}, 'Office Application Startup': {'Office Template Macros': '001', 'Office Test': '002', 'Outlook Forms': '003', 'Outlook Home Page': '004', 'Outlook Rules': '005', 'Add-ins': '006'}, 'Abuse Elevation Control Mechanism': {'Temporary Elevated Cloud Access': '005'}, 'Domain or Tenant Policy Modification': {'Trust Modification': '002'}, 'Hide Artifacts': {'Email Hiding Rules': '008'}, 'Impair Defenses': {'Disable or Modify Tools': '001', 'Disable or Modify Cloud Firewall': '007', 'Disable or Modify Cloud Logs': '008'}, 'Indicator Removal': {'Clear Mailbox Data': '008'}, 'Modify Cloud Compute Infrastructure': {'Create Snapshot': '001', 'Create Cloud Instance': '002', 'Delete Cloud Instance': '003', 'Revert Cloud Instance': '004', 'Modify Cloud Compute Configurations': '005'}, 'Use Alternate Authentication Material': {'Application Access Token': '001', 'Web Session Cookie': '004'}, 'Brute Force': {'Password Guessing': '001', 'Password Cracking': '002', 'Password Spraying': '003', 'Credential Stuffing': '004'}, 'Credentials from Password Stores': {'Cloud Secrets Management Stores': '006'}, 'Forge Web Credentials': {'Web Cookies': '001', 'SAML Tokens': '002'}, 'Unsecured Credentials': {'Credentials In Files': '001', 'Cloud Instance Metadata API': '005', 'Chat Messages': '008'}, 'Account Discovery': {'Email Account': '003', 'Cloud Account': '004'}, 'Permission Groups Discovery': {'Cloud Groups': '003'}, 'Software Discovery': {'Security Software Discovery': '001'}, 'Remote Services': {'Cloud Services': '007', 'Direct Cloud VM Connections': '008'}, 'Data from Information Repositories': {'Confluence': '001', 'Sharepoint': '002', 'Code Repositories': '003'}, 'Data Staged': {'Remote Data Staging': '002'}, 'Email Collection': {'Remote Email Collection': '002', 'Email Forwarding Rule': '003'}, 'Exfiltration Over Web Service': {'Exfiltration Over Webhook': '004'}, 'Defacement': {'External Defacement': '002'}, 'Endpoint Denial of Service': {'Service Exhaustion Flood': '002', 'Application Exhaustion Flood': '003', 'Application or System Exploitation': '004'}, 'Network Denial of Service': {'Direct Network Flood': '001', 'Reflection Amplification': '002'}}
subtechnique_faulty_name_to_correct_name = {'Cloud Api': 'Cloud API', 'Ssh Authorized Keys': 'SSH Authorized Keys', 'Multi Factor Authentication': 'Multi-Factor Authentication', 'Add Ins': 'Add-ins', 'Disable Or Modify Tools': 'Disable or Modify Tools', 'Disable Or Modify Cloud Firewall': 'Disable or Modify Cloud Firewall', 'Disable Or Modify Cloud Logs': 'Disable or Modify Cloud Logs', 'Saml Tokens': 'SAML Tokens', 'Cloud Instance Metadata Api': 'Cloud Instance Metadata API', 'Direct Cloud Vm Connections': 'Direct Cloud VM Connections', 'Application Or System Exploitation': 'Application or System Exploitation'}


def setup_logging() -> None:
    # Creating logger
    logger = logging.getLogger()

    logger.setLevel(logging.INFO)
    # Define the logs directory
    logs_directory = 'logs'
    # Create the logs directory if it does not exist
    os.makedirs(logs_directory, exist_ok=True)

    # Define the log file name
    current_date_and_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    logs_file = os.path.join(logs_directory, f'{current_date_and_time}.log')

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(thread)d - %(message)s')

    # # Console handler with specified level and formatter
    # console_handler = logging.StreamHandler()
    # console_handler.setLevel(logging.INFO)
    # console_handler.setFormatter(formatter)

    # File handler with specified level and formatter
    file_handler = logging.FileHandler(logs_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # Adding handlers to the logger
    # logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    # Suppress unwanted logs from HTTP requests
    http_logger = logging.getLogger('httpx')
    http_logger.setLevel(logging.WARNING)
    http_logger.propagate = False

    selenium_logger = logging.getLogger('WDM')
    selenium_logger.setLevel(logging.WARNING)


def dump_yaml(yaml_object: dict | list[dict]) -> str:
    formatted_yaml = yaml.safe_dump(yaml_object, default_flow_style=False, sort_keys=False, indent=4, width=1000).strip()

    # Manual adjustment to indent lines starting with "-"
    if isinstance(yaml_object, list):
        formatted_yaml = '\n'.join('    ' + line if not line.startswith('-') and line.strip().startswith('-') else line for line in formatted_yaml.splitlines())
    else:
        formatted_yaml = '\n'.join('    ' + line if line.strip().startswith('-') else line for line in formatted_yaml.splitlines())

    return formatted_yaml


def validate_event(event: str) -> str:
    event = re.sub(r'\([^)]*\)', '', event)
    if all([c.islower() for c in event if c.isalpha()]):
        splitted_event = event.split(' ')
        if len(splitted_event) == 3 and splitted_event[0] == 'aws':
            event = splitted_event[2]
        elif len(splitted_event) == 1:
            event = splitted_event[0]
        event_words = event.split('-')
        event = "".join([event_word.capitalize() for event_word in event_words])

    for i, char in enumerate(event):
        if char.isdigit():
            return event[:i]
    return event


def strip_value(value: str) -> str:
    value = value.strip()
    while (value.startswith('[') and value.endswith(']')) or (value.startswith('(') and value.endswith(')')) or (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1].strip()

    return value


def _reformat_content(d: dict) -> None:
    for key, value in d.items():
        stripped_key = strip_value(key)
        if key != stripped_key:
            d[stripped_key] = d.pop(key)
            key = stripped_key
        if isinstance(value, list) and len(value) == 1:
            d[key] = value[0]
            value = value[0]
        if isinstance(value, str):
            stripped_value = strip_value(value)
            if value != stripped_value:
                d[key] = stripped_value
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, str):
                    stripped_item = strip_value(item)
                    if item != stripped_item:
                        value[i] = stripped_item
                elif isinstance(item, dict):
                    logging.warning(f'Found a nested dictionary in {key} list.')
                    _reformat_content(item)
        elif isinstance(value, dict):
            _reformat_content(value)


def _sanitize_content(d: dict) -> None:
    keys_to_remove = []
    for key, value in d.items():
        lower_key = key.lower()
        if all(not char.isalnum() for char in lower_key) or lower_key.endswith('id') or lower_key.endswith('arn') or lower_key.endswith('date') or lower_key.endswith('time') or lower_key == 'timeframe' or lower_key == 'awsregion' or lower_key.startswith('sourceipaddress') or lower_key.startswith('useragent') or lower_key == 'eventtype' or lower_key == 'resourcetype': # or lower_key == 'errorcode' or lower_key == 'errormessage'
            keys_to_remove.append(key)
        # if isinstance(value, str):
        #     lower_stripped_value = value.lower()
        #     if lower_stripped_value == '*' or not lower_stripped_value:
        #         keys_to_remove.append(key)
        # elif isinstance(value, dict):
        if isinstance(value, dict):
            _sanitize_content(value)
    for key in keys_to_remove:
        del d[key]


def _remove_selection_from_condition(condition_string, selection_to_remove):
    # Set up the parser element for an entity (which is a sequence of alphabetic characters)
    selection = Word(alphas + "_")

    # Define the logical operators
    and_op = "and"
    or_op = "or"

    # Define the overall expression grammar
    condition = infixNotation(selection, [
        (and_op, 2, opAssoc.LEFT),
        (or_op, 2, opAssoc.LEFT),
    ])

    # Function to remove an entity from the parsed expression
    def remove_selection(parsed_condition, selection_to_remove):
        if isinstance(parsed_condition, str):
            return None if parsed_condition == selection_to_remove else parsed_condition
        elif isinstance(parsed_condition, ParseResults):
            sub_condition = []
            for sub in parsed_condition:
                result = remove_selection(sub, selection_to_remove)
                if result is not None:
                    sub_condition.append(result)

            if not sub_condition:
                return None

            # Reconstruct the expression, ensuring logical validity
            result_condition = []
            for i, part in enumerate(sub_condition):
                if isinstance(part, str) and part in (and_op, or_op):
                    # Avoid leading, trailing, or consecutive operators
                    if i == 0 or i == len(sub_condition) - 1 or isinstance(sub_condition[i - 1], str) and sub_condition[i - 1] in (
                    and_op, or_op):
                        continue
                result_condition.append(part)

            if len(result_condition) == 1:
                return result_condition[0]
            return ParseResults(result_condition)
        else:
            return parsed_condition

    # Convert the parsed expression back to a string
    def condition_to_string(parsed_condition):
        if isinstance(parsed_condition, str):
            return parsed_condition
        elif isinstance(parsed_condition, ParseResults):
            result = []
            for i, part in enumerate(parsed_condition):
                if isinstance(part, str) and part in (and_op, or_op):
                    result.append(part)
                else:
                    part_str = condition_to_string(part)
                    # Add parentheses only if part is an operator expression
                    if isinstance(part, ParseResults) and len(part) > 1:
                        # Check if the outer operator is the same as the inner operator
                        if i > 0 and parsed_condition[i - 1] in (and_op, or_op) and parsed_condition[i - 1] == part[1]:
                            result.append(part_str)
                        else:
                            result.append(f"({part_str})")
                    else:
                        result.append(part_str)
            return " ".join(result)
        else:
            return str(parsed_condition)

    # Parse the original expression
    parsed_condition = condition.parseString(condition_string, parseAll=True)[0]
    # Remove the specified entity
    result_condition = remove_selection(parsed_condition, selection_to_remove)
    # Convert the parsed expression back to string
    result_string = condition_to_string(result_condition)

    return result_string


def _remove_empty_values(d: dict) -> bool:
    removed = False
    keys_to_remove = []
    for key, value in d.items():
        if value is None or ((isinstance(value, list) or isinstance(value, dict)) and not value):
            keys_to_remove.append(key)
            removed = True
        elif isinstance(value, dict):
            removed = removed or _remove_empty_values(value)
    for key in keys_to_remove:
        del d[key]
        if 'condition' in d and key in d['condition']:
            d['condition'] = _remove_selection_from_condition(d['condition'], key)

    return removed


def _sanitize_rule(rule: dict) -> None:
    keys_to_remove = ['id', 'related', 'status', 'author', 'date', 'modified', 'references']
    for key in keys_to_remove:
        if key in rule:
            del rule[key]

    logsource_keys_to_remove = [key for key in rule['logsource'] if key not in {'product', 'service'}]
    for key in logsource_keys_to_remove:
        del rule['logsource'][key]

    if 'falsepositives' in rule:
        false_positives_to_remove = {'Low', 'High', 'Unlikely', 'Likely', 'Unknown'}
        if len(rule['falsepositives']) == 1 and rule['falsepositives'][0] in false_positives_to_remove:
            del rule['falsepositives']

    _sanitize_content(rule['detection'])
    while True:
        if not _remove_empty_values(rule['detection']):
            break


def _simplify_ttp(ttp: str) -> tuple[str, str] | None:
    ttp_upper = ttp.upper()
    subtechnique_id = re.search(r'(T\d{4})\.(\d{3})', ttp_upper)
    if subtechnique_id:
        if subtechnique_id.group(1) in technique_id_to_subtechnique_id_to_name and subtechnique_id.group(2) in technique_id_to_subtechnique_id_to_name[subtechnique_id.group(1)]:
            return f'attack.{subtechnique_id.group().lower()}', 'subtechnique'
        else:
            logging.warning(f'Invalid subtechnique ID in ttp: "{ttp}"')
            return None
    technique_id = re.search(r'T\d{4}', ttp_upper)
    if technique_id:
        if technique_id.group() in technique_id_to_name:
            return f'attack.{technique_id.group().lower()}', 'technique'
        else:
            logging.warning(f'Invalid technique ID: "{technique_id.group()}"')
            return None

    ttp_lower = ttp.lower()
    if 'subtechnique.' in ttp_lower or 'sub-technique.' in ttp_lower or 'sub_technique.' in ttp_lower:
        ttp_lower = re.sub(r'attack\.|subtechnique\.|sub-technique\.|sub_technique\.', '', ttp_lower)
        ttp_lower = ttp_lower.replace('_', ' ').replace('-', ' ').replace('"', '').replace("'", "").title()
        split_by_splitting_char = ttp_lower.split(':')
        if len(split_by_splitting_char) == 2:
            technique = split_by_splitting_char[0].strip()
            technique = technique_faulty_name_to_correct_name.get(technique, technique)
            technique_id = technique_name_to_id.get(technique, None)
            subtechnique = split_by_splitting_char[1].strip()
            subtechnique = subtechnique_faulty_name_to_correct_name.get(subtechnique, subtechnique)
            subtechnique_id = technique_name_to_subtechnique_name_to_id.get(technique, {}).get(subtechnique, None)
            if technique_id and subtechnique_id:
                return f'attack.{technique_id.lower()}.{subtechnique_id}', 'subtechnique'
            else:
                logging.warning(f'Invalid technique or subtechnique name in ttp: "{ttp}"')
                return None
        return None
    elif 'tactic.' in ttp_lower:
        ttp_lower = re.sub(r'attack\.|tactic\.', '', ttp_lower)
        ttp_title = ttp_lower.replace('_', ' ').replace('-', ' ').replace('"', '').replace("'", "").title()
        if ttp_title in tactic_name_to_id:
            return f'attack.{ttp_title.replace(" ", "_").lower()}', 'tactic'
        else:
            logging.warning(f'Invalid tactic name: "{ttp}"')
            return None
    elif 'technique.' in ttp_lower:
        ttp_lower = re.sub(r'attack\.|technique\.', '', ttp_lower)
        ttp_title = ttp_lower.replace('_', ' ').replace('-', ' ').replace('"', '').replace("'", "").title()
        ttp_title = technique_faulty_name_to_correct_name.get(ttp_title, ttp_title)
        if ttp_title in technique_name_to_id:
            return f'attack.{technique_name_to_id[ttp_title].lower()}', 'technique'
        else:
            logging.warning(f'Invalid technique name: "{ttp}"')
            return None

    ttp_title = ttp_lower.replace('attack.', '').replace('_', ' ').replace('-', ' ').replace('"', '').replace("'", "").title()
    if ttp_title in tactic_name_to_id:
        return f'attack.{ttp_title.lower().replace(" ", "_")}', 'tactic'
    elif ttp_title in technique_name_to_id:
        return f'attack.{technique_name_to_id[ttp_title].lower()}', 'technique'
    split_by_splitting_char = ttp_title.split(':')
    if len(split_by_splitting_char) == 2:
        technique = split_by_splitting_char[0].strip()
        technique = technique_faulty_name_to_correct_name.get(technique, technique)
        technique_id = technique_name_to_id.get(technique, None)
        subtechnique = split_by_splitting_char[1].strip()
        subtechnique = subtechnique_faulty_name_to_correct_name.get(subtechnique, subtechnique)
        subtechnique_id = technique_name_to_subtechnique_name_to_id.get(technique, {}).get(subtechnique, None)
        if technique_id and subtechnique_id:
            return f'attack.{technique_id.lower()}.{subtechnique_id}', 'subtechnique'
        else:
            logging.warning(f'Invalid technique or subtechnique name in ttp: "{ttp}"')
    else:
        logging.warning(f'Invalid TTP: {ttp}')
    return None


def _validate_ttps(rule: dict) -> None:
    tags = rule['tags']
    result = []
    current_type_to_ttp = {}

    def append_to_result():
        for current_type in ['tactic', 'technique', 'subtechnique']:
            if current_type in current_type_to_ttp and current_type_to_ttp[current_type] not in result:
                if current_type == 'subtechnique' and 'technique' not in current_type_to_ttp:
                    subtechnique_prefix = current_type_to_ttp['subtechnique'][:-4]
                    if subtechnique_prefix not in result:
                        result.append(subtechnique_prefix)
                result.append(current_type_to_ttp[current_type])

    for tag in tags:
        ttp_and_type = _simplify_ttp(tag)
        if ttp_and_type is not None:
            ttp, type = ttp_and_type
            if type not in current_type_to_ttp:
                current_type_to_ttp[type] = ttp
            else:
                append_to_result()
                current_type_to_ttp = {type: ttp}

    append_to_result()
    rule['tags'] = result


def validate_rule(rule: dict) -> dict:
    _reformat_content(rule['detection'])
    _sanitize_rule(rule)
    _validate_ttps(rule)

    # TODO: If there is no condition, add one

    return rule


# if __name__ == '__main__':
#     rules = [{'tags': ['attack.persistence']},
#              {'tags': ['attack.t1136']},
#              {'tags': ['attack.t1136.003']},
#              {'tags': ['attack.persistence', 'attack.t1136']},
#              {'tags': ['attack.persistence', 'attack.t1136.003']},
#              {'tags': ['attack.persistence', 'attack.t1136', 'attack.t1136.003']},
#              {'tags': ['attack.t1136', 'attack.t1136.003', 'attack.persistence']},
#              {'tags': ['attack.t1136', 'attack.t1136.003', 'attack.persistence', 'attack.t1496']},
#              {'tags': ['attack.t1136', 'attack.t1136.003', 'attack.persistence', 'attack.t1496', 'attack.impact']},
#              {'tags': ['attack.persistence', 'attack.t1136', 'attack.t1136.003', 'attack.impact', 'attack.t1496']},
#              {'tags': ['attack.persistence', 'attack.t1136', 'attack.t1136.003', 'attack.t1496', 'attack.impact']}]
#
#     expected_results = [['attack.persistence'],
#                         ['attack.t1136'],
#                         ['attack.t1136', 'attack.t1136.003'],
#                         ['attack.persistence', 'attack.t1136'],
#                         ['attack.persistence', 'attack.t1136', 'attack.t1136.003'],
#                         ['attack.persistence', 'attack.t1136', 'attack.t1136.003'],
#                         ['attack.persistence', 'attack.t1136', 'attack.t1136.003'],
#                         ['attack.persistence', 'attack.t1136', 'attack.t1136.003', 'attack.t1496'],
#                         ['attack.persistence', 'attack.t1136', 'attack.t1136.003', 'attack.impact', 'attack.t1496'],
#                         ['attack.persistence', 'attack.t1136', 'attack.t1136.003', 'attack.impact', 'attack.t1496'],
#                         ['attack.persistence', 'attack.t1136', 'attack.t1136.003', 'attack.impact', 'attack.t1496']]
#
#     for i, rule in enumerate(rules):
#         _validate_ttps(rule)
#         if rule['tags'] == expected_results[i]:
#             print(f"Rule {i + 1} passed.")
#         else:
#             print(f"Rule {i + 1} failed. Expected results: {expected_results[i]}. Actual results: {rule['tags']}.")