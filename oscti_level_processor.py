import logging
import re
from collections import Counter

from rule_optimizer import RuleOptimizer
from rule_selector import RuleSelector
from events_remover import EventsRemover
from ioc_extractor import IOCExtractor
from utils import sanitize_rule


class OSCTILevelProcessor:

    def __init__(self, rule_optimizer: RuleOptimizer = None, rule_selector: RuleSelector = None, events_remover: EventsRemover = None, ioc_extractor: IOCExtractor = None):
        self.rule_optimizer = rule_optimizer if rule_optimizer else RuleOptimizer()
        self.rule_selector = rule_selector if rule_selector else RuleSelector()
        self.events_remover = events_remover if events_remover else EventsRemover()
        self.ioc_extractor = ioc_extractor if ioc_extractor else IOCExtractor()

    @staticmethod
    def _extract_events(rule: dict) -> list[str]:
        event_names = []
        seen = set()

        def extract_event_names_recursive(d: dict) -> None:
            for key, value in d.items():
                if key == 'eventName':
                    if isinstance(value, dict):
                        continue
                    if isinstance(value, list):
                        for item in value:
                            if item not in seen:
                                event_names.append(item)
                                seen.add(item)
                    else:
                        if value not in seen:
                            event_names.append(value)
                            seen.add(value)
                elif isinstance(value, dict):
                    extract_event_names_recursive(value)

        extract_event_names_recursive(rule['detection'])
        return event_names

    @staticmethod
    def _generate_indexes_to_events(index_to_rule: dict[int, dict]) -> dict[tuple[int], list[str]]:
        # Create a dictionary to map each event name to the indices of the rules that contain them
        event_to_rule_indexes = {}
        for index, rule in index_to_rule.items():
            events = OSCTILevelProcessor._extract_events(rule)
            for event in events:
                if event not in event_to_rule_indexes:
                    event_to_rule_indexes[event] = (index,)
                else:
                    event_to_rule_indexes[event] = event_to_rule_indexes[event] + (index,)

        # Find rules with common eventNames
        indexes_to_events = {}
        for event, rule_indexes in event_to_rule_indexes.items():
            if len(rule_indexes) > 1:
                if rule_indexes not in indexes_to_events:
                    indexes_to_events[rule_indexes] = []
                indexes_to_events[rule_indexes].append(event)

        return indexes_to_events

    @staticmethod
    def _reformat_ioc_object(ioc: dict) -> dict:
        def is_valid_ip_address(ip_address: str) -> bool:
            host_bytes = ip_address.split('.')

            # Check if there are exactly 4 segments
            if len(host_bytes) != 4:
                return False

            # Check if all segments are valid integers in the range 0-255
            for byte in host_bytes:
                if not byte.isdigit() or not 0 <= int(byte) <= 255:
                    return False

            return True

        # Normalize IP addresses
        ip_addresses = []
        ip_keys = [
            'ip', 'IP', 'ips', 'IPs', 'address', 'Address', 'addresses', 'Addresses', 'ip address', 'ip addresses',
            'IP address', 'IP addresses', 'IP Address', 'IP Addresses', 'ip-address', 'ip-addresses', 'IP-address',
            'IP-addresses', 'IP-Address', 'IP-Addresses', 'ip_address', 'IP_address', 'IP_Address', 'ip_addresses',
            'IP_addresses', 'IP_Addresses', 'ipaddress', 'IPaddress', 'IPAddress', 'ipaddresses', 'IPaddresses',
            'IPAddresses'
        ]

        for key in ip_keys:
            if not ioc:
                break
            if key in ioc:
                if isinstance(ioc[key], str):
                    ip_addresses.append(ioc[key])
                else:
                    ip_addresses.extend(ioc[key])
                del ioc[key]

        ip_addresses = [ip_address.replace('[', '').replace(']', '').strip("""'"()""") for ip_address in ip_addresses]
        ip_addresses = [ip_address for ip_address in set(ip_addresses) if is_valid_ip_address(ip_address)]

        if len(ip_addresses) == 1:
            ioc['ip_address'] = ip_addresses[0]
        elif len(ip_addresses) > 1:
            ioc['ip_addresses'] = ip_addresses

        # Normalize user agents
        user_agents = []
        user_agent_keys = [
            'ua', 'UA', 'user_agent', 'User_Agent', 'user_agents', 'User_Agents', 'useragent', 'UserAgent',
            'useragents',
            'UserAgents', 'user agent', 'user agents', 'User agent', 'User agents', 'User Agent', 'User Agents',
            'user-agent', 'user-agents', 'User-agent', 'User-agents', 'User-Agent', 'User-Agents'
        ]

        for key in user_agent_keys:
            if not ioc:
                break
            if key in ioc:
                if isinstance(ioc[key], str):
                    user_agents.append(ioc[key])
                else:
                    user_agents.extend(ioc[key])
                del ioc[key]

        user_agents = [user_agent.strip("""'"()[]""") for user_agent in user_agents]
        user_agents = list(set(user_agents))

        if len(user_agents) == 1:
            ioc['user_agent'] = user_agents[0]
        elif len(user_agents) > 1:
            ioc['user_agents'] = user_agents

        return ioc

    def process_rules(self, rules: dict | list[dict], text: str) -> dict | list[dict]:
        rules = self.rule_optimizer.optimize_rules(rules)
        index_to_rule = {index: sanitize_rule(rule) for index, rule in enumerate(rules)}
        indexes_to_events = OSCTILevelProcessor._generate_indexes_to_events(index_to_rule)

        if indexes_to_events:
            for rule_indexes_tuple, event_names_list in indexes_to_events.items():
                rule_indexes_string = ', '.join(str(index) for index in rule_indexes_tuple)
                event_names_string = ', '.join(event_names_list)
                logging.info(f"Candidates {rule_indexes_string} share the following eventNames: {event_names_string}.")

                updated_rules_with_common_event_names_indexes_list = [index for index in rule_indexes_tuple if index in index_to_rule]
                if len(updated_rules_with_common_event_names_indexes_list) > 1:
                    updated_rules_with_common_event_names_indexes_and_objects_list = [(index, index_to_rule[index]) for index in updated_rules_with_common_event_names_indexes_list]
                    selected_rule_index = self.rule_selector.select_rule(event_names_list, updated_rules_with_common_event_names_indexes_and_objects_list)
                    logging.info(f"From rules {updated_rules_with_common_event_names_indexes_list}, rule {selected_rule_index} was selected to retain the common eventNames.")
                    rules_to_edit_indexes = [index for index in updated_rules_with_common_event_names_indexes_list if index != selected_rule_index]
                    for rule_to_edit_index in rules_to_edit_indexes:
                        rule_to_edit = index_to_rule[rule_to_edit_index]
                        rule_to_edit_events = OSCTILevelProcessor._extract_events(rule_to_edit)
                        if Counter(rule_to_edit_events) == Counter(event_names_list):
                            del index_to_rule[rule_to_edit_index]
                            logging.info(f"Rule Number {rule_to_edit_index} was removed.")
                        else:
                            edited_rule = self.events_remover.remove_events(event_names_list, rule_to_edit)
                            logging.info(f"Rule Number {rule_to_edit_index} was edited to remove the common eventName(s).")
                            edited_rule = sanitize_rule(edited_rule)
                            index_to_rule[rule_to_edit_index] = edited_rule

        iocs = self.ioc_extractor.extract_iocs(text)
        if iocs:
            # iocs = OSCTILevelProcessor._reformat_ioc_object(iocs)
            logging.info("IoCs have been successfully extracted from the OSCTI formatted text.")
            ioc_ip_inserted, ioc_ua_inserted = False, False
            for type, values in iocs.items():
                if "AWS Internal" in values:
                    values.remove("AWS Internal")
                    # TODO: Implement custom integration for "AWS Internal"
                if type == 'ip_address' or type == 'ip_addresses':
                    for rule in index_to_rule.values():
                        rule['detection']["selection_ioc_ip"] = {"sourceIPAddress": values}
                    ioc_ip_inserted = True
                elif type == 'user_agent' or type == 'user_agents':
                    for rule in index_to_rule.values():
                        rule['detection']["selection_ioc_ua"] = {"userAgent|contains": values}
                    ioc_ua_inserted = True
            for rule in index_to_rule.values():
                if 'condition' in rule['detection']:
                    condition_string = rule['detection']['condition']
                    del rule['detection']['condition']
                    if bool(re.search(r'^(\w+)(?: or \w+)+$', condition_string)):
                        condition_string = f"({condition_string})"
                    if ioc_ip_inserted and ioc_ua_inserted:
                        rule['detection'][
                            'condition'] = f"{condition_string} and (selection_ioc_ip or selection_ioc_ua)"
                    elif ioc_ip_inserted:
                        rule['detection']['condition'] = f"{condition_string} and selection_ioc_ip"
                    elif ioc_ua_inserted:
                        rule['detection']['condition'] = f"{condition_string} and selection_ioc_ua"
                    else:
                        rule['detection']['condition'] = condition_string
            logging.info("IoCs have been successfully enhanced in the optimized Sigma rules.")

        rules = list(index_to_rule.values())
        if len(rules) == 1:
            rules = rules[0]

        return rules
