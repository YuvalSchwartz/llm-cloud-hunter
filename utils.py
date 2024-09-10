import logging
import os
import re
from datetime import datetime
import yaml


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
    formatted_yaml = yaml.safe_dump(yaml_object, default_flow_style=False, sort_keys=False, width=1000).strip()

    # Manual adjustment to indent lines starting with "-"
    if isinstance(yaml_object, list):
        formatted_yaml = '\n'.join('  ' + line if not line.startswith('-') and line.strip().startswith('-') else line for line in formatted_yaml.splitlines())
    else:
        formatted_yaml = '\n'.join('  ' + line if line.strip().startswith('-') else line for line in formatted_yaml.splitlines())

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


def _reformat_detection_lists(detection: dict) -> None:
    for key, value in detection.items():
        if isinstance(value, dict):
            _reformat_detection_lists(value)
        elif isinstance(value, list) and len(value) == 1:
            detection[key] = value[0]


def _sanitize_rule(rule: dict) -> None:
    def _sanitize_detection(detection: dict) -> None:
        keys_to_remove = []
        for key, value in detection.items():
            lower_key = key.lower()
            if lower_key.endswith('id') or lower_key.endswith('arn') or lower_key.endswith('date') or lower_key.endswith('time') or lower_key == 'timeframe' or lower_key == 'awsregion' or lower_key.startswith('sourceipaddress') or lower_key.startswith('useragent') or lower_key == 'eventtype' or lower_key == 'resourcetype': # or lower_key == 'errorcode' or lower_key == 'errormessage'
                keys_to_remove.append(key)
            if isinstance(value, str):
                lower_stripped_value = value.lower().strip("' ")
                if lower_stripped_value == '*' or not lower_stripped_value:
                    keys_to_remove.append(key)
            elif isinstance(value, dict):
                if value:
                    _sanitize_detection(value)
                else:
                    keys_to_remove.append(key)
        for key in keys_to_remove:
            if key in detection:
                del detection[key]

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

    _sanitize_detection(rule['detection'])


def _complete_missing_techniques(rule: dict) -> None:
    ttps = rule['tags']
    updated_ttps = []
    for ttp in ttps:
        updated_ttps.append(ttp)
        ttp_lower = ttp.lower().replace('attack.', '')
        if ttp_lower.startswith('t') and '.' in ttp_lower:
                technique = 'attack.' + ttp_lower.split('.')[0]
                if technique not in updated_ttps:
                    updated_ttps.insert(len(updated_ttps) - 1, technique)

    rule['tags'] = updated_ttps


def validate_rule(rule: dict) -> dict:
    _reformat_detection_lists(rule['detection'])
    _sanitize_rule(rule)
    _complete_missing_techniques(rule)

    return rule
