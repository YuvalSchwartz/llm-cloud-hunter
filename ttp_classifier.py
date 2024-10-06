import json
import logging
import os
import re
from openai import OpenAI
from openai.types.chat import ChatCompletion

from prompts.ttp_classification_prompts import ttp_extracting_system_prompt, generate_ttp_extracting_user_prompt
from utils import validate_event, tactic_name_to_id, technique_id_to_name, technique_faulty_name_to_correct_name, technique_name_to_id, technique_id_to_subtechnique_id_to_name, subtechnique_faulty_name_to_correct_name, technique_name_to_subtechnique_name_to_id


class TTPClassifier:
    tactic_id_to_name = {'TA0001': 'Initial Access', 'TA0002': 'Execution', 'TA0003': 'Persistence', 'TA0004': 'Privilege Escalation', 'TA0005': 'Defense Evasion', 'TA0006': 'Credential Access', 'TA0007': 'Discovery', 'TA0008': 'Lateral Movement', 'TA0009': 'Collection', 'TA0010': 'Exfiltration', 'TA0040': 'Impact'}

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
    def _expand_ttp(type: str, ttp: str, parent: str = None) -> str:
        if type == 'tactic':
            id = re.search(r'TA\d{4}', ttp, re.IGNORECASE)
            if id:
                return f'{TTPClassifier.tactic_id_to_name[id.group().upper()]} ({id.group().upper()})'
            else:
                ttp = re.sub(r'attack\.|tactic\.', '', ttp, re.IGNORECASE)
                ttp = ttp.replace('_', ' ').replace('-', ' ').replace('"', '').replace("'", "").title()
                if ttp in tactic_name_to_id:
                    return f'{ttp} ({tactic_name_to_id[ttp]})'
        elif type == 'technique':
            id = re.search(r'T\d{4}', ttp, re.IGNORECASE)
            if id:
                return f'{technique_id_to_name[id.group().upper()]} ({id.group().upper()})'
            else:
                ttp = re.sub(r'attack\.|technique\.', '', ttp, re.IGNORECASE)
                ttp = ttp.replace('_', ' ').replace('-', ' ').replace('"', '').replace("'", "").title()
                ttp = technique_faulty_name_to_correct_name.get(ttp, ttp)
                if ttp in technique_name_to_id:
                    return f'{ttp} ({technique_name_to_id[ttp]})'
        elif type == 'subtechnique':
            ids = re.search(r'(T\d{4})[.:/\\](\d{3})', ttp, re.IGNORECASE)
            if ids:
                return f'{technique_id_to_name[ids.group(1).upper()]}: {technique_id_to_subtechnique_id_to_name[ids.group(1).upper()][ids.group(2)]} ({ids.group(1).upper()}.{ids.group(2)})'
            else:
                ttp = re.sub(r'attack\.|subtechnique\.', '', ttp, re.IGNORECASE)
                ttp = ttp.replace('_', ' ').replace('-', ' ').replace('"', '').replace("'", "").title()
                split_by_colon = ttp.split(':')
                if len(split_by_colon) == 2:
                    technique = split_by_colon[0].strip()
                    technique = technique_faulty_name_to_correct_name.get(technique, technique)
                    technique_id = technique_name_to_id.get(technique, None)
                    subtechnique = split_by_colon[1].strip()
                    subtechnique = subtechnique_faulty_name_to_correct_name.get(subtechnique, subtechnique)
                    subtechnique_id = technique_name_to_subtechnique_name_to_id.get(technique, {}).get(subtechnique, None)
                    if technique_id and subtechnique_id:
                        return f'{technique}: {subtechnique} ({technique_id}.{subtechnique_id})'
                    else:
                        return f'{technique}: {subtechnique}'
                elif parent is not None:
                    parent_id = re.search(r'T\d{4}', parent)
                    if parent_id:
                        parent = technique_id_to_name[parent_id.group()]
                        if ttp in technique_name_to_subtechnique_name_to_id[parent]:
                            return f'{parent}: {ttp} ({parent_id.group()}.{technique_name_to_subtechnique_name_to_id[parent][ttp]})'
        return ttp

    @staticmethod
    def _validate_event_to_ttps(event_to_ttps: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
        reformatted_event_to_ttps = {}
        for event, ttps in event_to_ttps.items():
            # TODO: check and improve the validation, for now, the following line is a temporary solution
            if len(event) < 3 or ttps is None or event == 'S' or event == 's':
                logging.warning(f"Invalid event: {event} or TTPs: {ttps}")
                continue
            event = validate_event(event)
            reformatted_event_to_ttps[event] = {}
            for type, value in ttps.items():
                type = type.lower().replace('name', '').replace('id', '').replace('-', '').replace('_', '').replace(' ', '')
                if value:
                    if type == 'subtechnique' and 'technique' in reformatted_event_to_ttps[event]:
                        value = TTPClassifier._expand_ttp(type, value, reformatted_event_to_ttps[event]['technique'])
                    else:
                        value = TTPClassifier._expand_ttp(type, value)
                    reformatted_event_to_ttps[event][type] = value

        return reformatted_event_to_ttps

    # @staticmethod
    # def _simplify_ttps(event_to_ttps: dict[str, dict[str, str]]) -> None:
    #     for event, ttps in event_to_ttps.items():
    #         if 'tactic_name' in ttps:
    #             tactic_name = ttps['tactic_name'].upper().replace('ATTACK.', '').replace("'", "")
    #             if re.match(r'^TA\d{4}$', tactic_name) and tactic_name in tactic_id_to_name:
    #                 tactic_name = tactic_id_to_name[tactic_name]
    #             ttps['tactic_name'] = f'attack.{tactic_name.lower().replace(" ", "_")}'
    #         if 'technique_id' in ttps:
    #             technique_id = ttps['technique_id'].title().replace('Attack.', '').replace("'", "").replace('_', ' ')
    #             if re.match(r'^.*\..*$', technique_id):
    #                 technique_id = technique_id.split('.')[-1]
    #             if not re.match(r'^T\d{4}$', technique_id) and technique_id in technique_name_to_id:
    #                 technique_id = technique_name_to_id[technique_id]
    #             elif re.match(r'^[A-Za-z ]+\(T\d{4}\)$', technique_id):
    #                 technique_id = technique_id.split('(')[-1].split(')')[0]
    #             ttps['technique_id'] = f'attack.{technique_id.lower()}'
    #         if 'subtechnique_id' in ttps:
    #             subtechnique_id = ttps['subtechnique_id'].title().replace('Attack.', '').replace("'", "").replace('_', ' ')
    #             if re.match(r'^.*\..*\..*$', subtechnique_id):
    #                 subtechnique_id = subtechnique_id.split('.')[-2] + '.' + subtechnique_id.split('.')[-1]
    #             if re.match(r'^\d{3}$', subtechnique_id):
    #                 ttps['subtechnique_id'] = f'{ttps["technique_id"]}.{subtechnique_id}'
    #             else:
    #                 if re.match(r'^[A-Za-z :]+\(T\d{4}\.\d{3}\)$', subtechnique_id):
    #                     subtechnique_id = subtechnique_id.split('(')[-1].split(')')[0]
    #                 ttps['subtechnique_id'] = f'attack.{subtechnique_id.lower()}'

    def classify_api_call_ttp(self, event_to_source: dict[str, str], paragraph: str) -> dict[str, dict[str, str]] | None:
        messages = TTPClassifier._generate_ttp_classification_messages(event_to_source, paragraph)

        try:
            response = self._send_ttp_classification_request(messages)
        except Exception as e:
            logging.error(f"Error extracting TTPs: {e}")
            return None

        response = response.choices[0].message.content
        event_to_ttps = json.loads(response)
        event_to_ttps = TTPClassifier._validate_event_to_ttps(event_to_ttps)

        return event_to_ttps
