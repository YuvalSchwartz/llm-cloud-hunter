import logging
import re
from collections import Counter
from copy import deepcopy

from rule_optimizer import RuleOptimizer
from rule_selector import RuleSelector
from events_remover import EventsRemover
from ioc_extractor import IOCExtractor


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
                    if isinstance(value, str) and value not in seen:
                        event_names.append(value)
                        seen.add(value)
                    if isinstance(value, list):
                        for item in value:
                            if item not in seen:
                                event_names.append(item)
                                seen.add(item)
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

    def process_rules(self, rules: dict | list[dict], markdown: str) -> dict | list[dict]:
        rules = self.rule_optimizer.optimize_rules(rules)

        index_to_rule = {index: rule for index, rule in enumerate(rules)}
        indexes_to_events = OSCTILevelProcessor._generate_indexes_to_events(index_to_rule)
        if indexes_to_events:
            for rule_indexes_tuple, event_names_list in indexes_to_events.items():
                logging.info(f"Candidates {', '.join(str(index) for index in rule_indexes_tuple)} share the following eventNames: {', '.join(event_names_list)}.")
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
                            index_to_rule[rule_to_edit_index] = edited_rule
            rules = list(index_to_rule.values())

        ioc = self.ioc_extractor.extract_iocs(markdown)
        if ioc.ip_addresses or ioc.user_agents:
            for rule in rules:
                if ioc.ip_addresses:
                    rule['detection']["selection_ioc_ip"] = {"sourceIPAddress": deepcopy(ioc.ip_addresses)}
                if ioc.user_agents:
                    rule['detection']["selection_ioc_ua"] = {"userAgent|contains": deepcopy(ioc.user_agents)}

                # if 'condition' in rule['detection']:
                #     condition = rule['detection']['condition']
                #     condition = f"({condition})" if bool(re.search(r'^(\w+)(?: or \w+)+$', condition)) else condition
                #     del rule['detection']['condition']
                #     if ioc.ip_addresses and ioc.user_agents:
                #         rule['detection']['condition'] = f"{condition} and (selection_ioc_ip or selection_ioc_ua)"
                #     elif ioc.ip_addresses and not ioc.user_agents:
                #         rule['detection']['condition'] = f"{condition} and selection_ioc_ip"
                #     elif not ioc.ip_addresses and ioc.user_agents:
                #         rule['detection']['condition'] = f"{condition} and selection_ioc_ua"

                condition = rule['detection']['condition']
                condition = f"({condition})" if bool(re.search(r'^(\w+)(?: or \w+)+$', condition)) else condition
                del rule['detection']['condition']
                if ioc.ip_addresses and ioc.user_agents:
                    rule['detection']['condition'] = f"{condition} and (selection_ioc_ip or selection_ioc_ua)"
                elif ioc.ip_addresses and not ioc.user_agents:
                    rule['detection']['condition'] = f"{condition} and selection_ioc_ip"
                elif not ioc.ip_addresses and ioc.user_agents:
                    rule['detection']['condition'] = f"{condition} and selection_ioc_ua"

        if len(rules) == 1:
            rules = rules[0]

        return rules
