import os
import re
import yaml

from utils import tactic_name_to_id, technique_id_to_name, technique_id_to_subtechnique_id_to_name


# def print_entities(rule_objects_list: list[dict]):
#     def add_detection_entities_rec(rule_object: dict, api_calls: list[str], iocs: list[str], others: list[str]):
#         for key, value in rule_object.items():
#             key = key.split("|")[0]
#             if key == "condition":
#                 continue
#             if isinstance(value, str) or isinstance(value, int):
#                 if key == "eventName":
#                     if value not in api_calls:
#                         api_calls.append(value)
#                 elif key == "sourceIPAddress" or key == "userAgent":
#                     if value not in iocs:
#                         iocs.append(value)
#                 else:
#                     if value not in others:
#                         others.append(value)
#             elif isinstance(value, list):
#                 for item in value:
#                     if key == "eventName":
#                         if item not in api_calls:
#                             api_calls.append(item)
#                     elif key == "sourceIPAddress" or key == "userAgent":
#                         if item not in iocs:
#                             iocs.append(item)
#                     else:
#                         if item not in others:
#                             others.append(item)
#             elif isinstance(value, dict):
#                 add_detection_entities_rec(value, api_calls, iocs, others)
#
#     api_calls, tactics, techniques, sub_techniques, iocs, others = [], [], [], [], [], []
#     for rule_object in rule_objects_list:
#         for tag in rule_object["tags"]:
#             tag = tag.lower().replace("attack.", "")
#             if not tag.startswith("t"):
#                 tag = tag.replace("_", " ").replace("-", " ").title()
#                 if tag not in tactic_name_to_id:
#                     continue
#                 tag = f"{tag} ({tactic_name_to_id[tag]})"
#                 if tag not in tactics:
#                     tactics.append(tag)
#             elif "." not in tag:
#                 tag = tag.upper()
#                 if tag not in technique_id_to_name:
#                     continue
#                 tag = f"{technique_id_to_name[tag]} ({tag})"
#                 if tag not in techniques:
#                     techniques.append(tag)
#             else:
#                 tag = tag.upper()
#                 technique, sub_technique = tag.split(".")
#                 if technique not in technique_id_to_subtechniques:
#                     continue
#                 if sub_technique not in technique_id_to_subtechniques[technique]:
#                     continue
#                 tag = f"{technique_id_to_name[technique]}: {technique_id_to_subtechniques[technique][sub_technique]} ({tag})"
#                 if tag not in sub_techniques:
#                     sub_techniques.append(tag)
#         add_detection_entities_rec(rule_object["detection"], api_calls, iocs, others)
#     print("API Call:")
#     for api_call in api_calls:
#         print(api_call)
#     print("\nTactic:")
#     for tactic in tactics:
#         print(tactic)
#     print("\nTechnique:")
#     for technique in techniques:
#         print(technique)
#     print("\nSub-techniques:")
#     for sub_technique in sub_techniques:
#         print(sub_technique)
#     print("\nIoC:")
#     for ioc in iocs:
#         print(ioc)
#     print("\nOther:")
#     for other in others:
#         print(other)
#
#
# def print_entity_sigma_field(rule_objects_list: list[dict]):
#     def add_entity_sigma_field_rec(rule_object: dict, results: list[str]):
#         for key, value in rule_object.items():
#             key = key.split("|")[0]
#             if key == "condition":
#                 continue
#             if isinstance(value, str):
#                 if f"{value} ↔ {key}" not in results:
#                     results.add(f"{value} ↔ {key}")
#             elif isinstance(value, list):
#                 for item in value:
#                     if f"{item} ↔ {key}" not in results:
#                         results.add(f"{item} ↔ {key}")
#             elif isinstance(value, dict):
#                 add_entity_sigma_field_rec(value, results)
#
#     non_ttp_entitites = set()
#     ttp_entitites = set()
#     for rule_object in rule_objects_list:
#         for tag in rule_object["tags"]:
#             tag = tag.replace("attack.", "")
#             tag = tag.replace("_", " ")
#             tag = tag.title()
#             if tag in tactic_name_to_id:
#                 tag = f"{tag} ({tactic_name_to_id[tag]})"
#             if tag in technique_id_to_name:
#                 tag = f"{technique_id_to_name[tag]} ({tag})"
#             if len(tag) == 9 and tag[0] == 'T' and tag[1:5].isdigit() and tag[5] == "." and tag[6:].isdigit():
#                 technique, sub_technique = tag.split(".")
#                 if technique not in technique_id_to_subtechniques:
#                     continue
#                 if sub_technique not in technique_id_to_subtechniques[technique]:
#                     continue
#                 tag = f"{technique_id_to_name[technique]}: {technique_id_to_subtechniques[technique][sub_technique]} ({tag})"
#             ttp_entitites.add(f"{tag} ↔ tags")
#         add_entity_sigma_field_rec(rule_object["detection"], non_ttp_entitites)
#     print("\nEntity ↔ Sigma Field:")
#     for non_ttp_entity in non_ttp_entitites:
#         print(non_ttp_entity)
#     print("\nTTP ↔ Sigma Field:")
#     for ttp_entity in ttp_entitites:
#         print(ttp_entity)
#
#
# def add_api_call_rec(rule_object: dict, api_calls: list[str]):
#     for key, value in rule_object.items():
#         key = key.split("|")[0]
#         if key == "condition":
#             continue
#         if isinstance(value, str):
#             if key == "eventName":
#                 if value not in api_calls:
#                     api_calls.append(value)
#         elif isinstance(value, list):
#             for item in value:
#                 if key == "eventName":
#                     if item not in api_calls:
#                         api_calls.append(item)
#         elif isinstance(value, dict):
#             add_api_call_rec(value, api_calls)
#
#
# def add_ioc_rec(rule_object: dict, iocs: list[str]):
#     for key, value in rule_object.items():
#         key = key.split("|")[0]
#         if key == "condition":
#             continue
#         if isinstance(value, str):
#             if key == "sourceIPAddress" or key == "userAgent":
#                 if value not in iocs:
#                     iocs.append(value)
#         elif isinstance(value, list):
#             for item in value:
#                 if key == "sourceIPAddress" or key == "userAgent":
#                     if item not in iocs:
#                         iocs.append(item)
#         elif isinstance(value, dict):
#             add_ioc_rec(value, iocs)
#
#
# def print_api_call_tactic(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ Tactic:")
#     for rule_object in rule_objects_list:
#         tactics = []
#         for tag in rule_object["tags"]:
#             tag = tag.lower().replace("attack.", "")
#             if not tag.startswith("t"):
#                 tag = tag.replace("_", " ").replace("-", " ").title()
#                 if tag not in tactic_name_to_id:
#                     continue
#                 tag = f"{tag} ({tactic_name_to_id[tag]})"
#                 if tag not in tactics:
#                     tactics.append(tag)
#         api_calls = []
#         add_api_call_rec(rule_object["detection"], api_calls)
#         for api_call in api_calls:
#             for tactic in tactics:
#                 print(f"{api_call} ↔ {tactic}")
#
#
# def print_api_call_technique(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ Technique:")
#     for rule_object in rule_objects_list:
#         techniques = []
#         for tag in rule_object["tags"]:
#             tag = tag.lower().replace("attack.", "")
#             if tag[0] == 't' and tag[1:].isdigit():
#                 tag = tag.upper()
#                 if tag not in technique_id_to_name:
#                     continue
#                 tag = f"{technique_id_to_name[tag]} ({tag})"
#                 if tag not in techniques:
#                     techniques.append(tag)
#         api_calls = []
#         add_api_call_rec(rule_object["detection"], api_calls)
#         for api_call in api_calls:
#             for technique in techniques:
#                 print(f"{api_call} ↔ {technique}")
#
#
# def print_api_call_sub_technique(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ Sub-technique:")
#     for rule_object in rule_objects_list:
#         sub_techniques = []
#         for tag in rule_object["tags"]:
#             tag = tag.lower().replace("attack.", "")
#             if len(tag) == 9 and tag[0] == 't' and tag[1:5].isdigit() and tag[5] == "." and tag[6:].isdigit():
#                 tag = tag.upper()
#                 technique, sub_technique = tag.split(".")
#                 if technique not in technique_id_to_subtechniques:
#                     continue
#                 if sub_technique not in technique_id_to_subtechniques[technique]:
#                     continue
#                 tag = f"{technique_id_to_name[technique]}: {technique_id_to_subtechniques[technique][sub_technique]} ({tag})"
#                 if tag not in sub_techniques:
#                     sub_techniques.append(tag)
#         api_calls = []
#         add_api_call_rec(rule_object["detection"], api_calls)
#         for api_call in api_calls:
#             for sub_technique in sub_techniques:
#                 print(f"{api_call} ↔ {sub_technique}")
#
#
# def print_api_call_ioc(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ IoC:")
#     for rule_object in rule_objects_list:
#         api_calls = []
#         add_api_call_rec(rule_object["detection"], api_calls)
#         iocs = []
#         add_ioc_rec(rule_object["detection"], iocs)
#         for api_call in api_calls:
#             for ioc in iocs:
#                 print(f"{api_call} ↔ {ioc}")
#
#
# def print_api_call_other(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ Other:")
#     def add_other_rec(rule_object: dict, others: list[str]):
#         for key, value in rule_object.items():
#             key = key.split("|")[0]
#             if isinstance(value, str) or isinstance(value, int):
#                 if key != "eventName" and key != "sourceIPAddress" and key != "userAgent":
#                     if value not in others:
#                         others.append(value)
#             elif isinstance(value, list):
#                 for item in value:
#                     if key != "eventName" and key != "sourceIPAddress" and key != "userAgent":
#                         if item not in others:
#                             others.append(item)
#             elif isinstance(value, dict):
#                 add_ioc_rec(value, others)
#
#     for rule_object in rule_objects_list:
#         for key, value in rule_object["detection"].items():
#             key = key.split("|")[0]
#             if key == "condition":
#                 continue
#             api_calls = []
#             add_api_call_rec(value, api_calls)
#             others = []
#             add_other_rec(value, others)
#             for api_call in api_calls:
#                 for other in others:
#                     print(f"{api_call} ↔ {other}")
#
#
# def get_text_similarity(text1: str, text2: str) -> float:
#     # from dotenv import load_dotenv
#     # import os
#     # from openai import OpenAI
#     # from sklearn.metrics.pairwise import cosine_similarity
#     #
#     # load_dotenv()
#     # client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
#     # sentence1 = "The capital of France is Paris"
#     # sentence2 = "Paris is the capital of France"
#     # embedding1 = client.embeddings.create(input=[sentence1], model="text-embedding-3-large").data[0].embedding
#     # embedding2 = client.embeddings.create(input=[sentence2], model="text-embedding-3-large").data[0].embedding
#     # return cosine_similarity([embedding1], [embedding2])[0][0]
#     model = SentenceTransformer('Lajavaness/bilingual-embedding-large', trust_remote_code=True)
#     embeddings = model.encode([text1, text2])
#     similarities = model.similarity(embeddings, embeddings)
#
#     return similarities[0][1].item()


def get_ttps(tags: list[str]) -> tuple[set[str], set[str], set[str]]:
    tactics, techniques, subtechniques = set(), set(), set()

    for tag in tags:
        tag = tag.lower().replace('attack.', '')
        if not tag.startswith('t'):
            tag = tag.replace('_', ' ').replace('-', ' ').title()
            if tag in tactic_name_to_id:
                tactics.add(f'{tag} ({tactic_name_to_id[tag]})')
        elif '.' not in tag:
            tag = tag.upper()
            if tag in technique_id_to_name:
                techniques.add(f'{technique_id_to_name[tag]} ({tag})')
        else:
            tag = tag.upper()
            technique, sub_technique = tag.split('.')
            if technique in technique_id_to_subtechnique_id_to_name and sub_technique in technique_id_to_subtechnique_id_to_name[technique]:
                techniques.add(f'{technique_id_to_name[technique]} ({technique})')
                subtechniques.add(f'{technique_id_to_name[technique]}: {technique_id_to_subtechnique_id_to_name[technique][sub_technique]} ({tag})')

    return tactics, techniques, subtechniques


def extract_logsource_data(logsource: dict) -> tuple[set[str], set[str], set[str], set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    product_field_names, service_field_names = set(), set()
    products, services = set(), set()
    product_field_names_and_products, service_field_names_and_services = set(), set()

    for key, value in logsource.items():
        if key == 'product':
            add_to_sets(key, value, product_field_names, products, product_field_names_and_products)
        elif key == 'service':
            add_to_sets(key, value, service_field_names, services, service_field_names_and_services)

    return product_field_names, service_field_names, products, services, product_field_names_and_products, service_field_names_and_services


# def match_special_string(special_string: str, candidate: str) -> bool:
#     # Convert special string to regex
#     pattern = re.escape(special_string).replace(r'\*', '.*')
#     # Add start and end anchors to ensure full string match
#     pattern = f'^{pattern}$'
#     # Check if candidate matches the pattern
#     return re.match(pattern, candidate) is not None
#
#
# def calculate_performance_metrics(ground_truth_data: Set[str], output_data: Set[str]) -> Tuple[int, Tuple[float, float, float]]:
#     support = len(ground_truth_data)
#
#     TP = 0
#     FN = 0
#
#     # Mark which items have been matched
#     matched_output = set()
#
#     # Calculate TP and FN
#     for ground_truth_item in ground_truth_data:
#         match_found = False
#         for output_item in output_data:
#             if match_special_string(ground_truth_item, output_item) or match_special_string(output_item, ground_truth_item):
#                 TP += 1
#                 matched_output.add(output_item)
#                 match_found = True
#                 break
#         if not match_found:
#             FN += 1
#
#     # Calculate FP (output items that were not matched with ground truth)
#     FP = len(output_data - matched_output)
#
#     precision = TP / (TP + FP) if (TP + FP) > 0 else 0
#     recall = TP / (TP + FN) if (TP + FN) > 0 else 0
#     f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
#
#     return support, (precision, recall, f1_score)


def add_to_sets(key: str, value: str | list[str], keys_set: set[str], values_set: set[str], keys_and_values_set: set[tuple[str, str]]) -> None:
    if key.endswith('|contains'):
        key = key[:-9]
        prefix, suffix = '*', '*'
    elif key.endswith('|startswith'):
        key = key[:-10]
        prefix, suffix = '', '*'
    elif key.endswith('|endswith'):
        key = key[:-8]
        prefix, suffix = '*', ''
    else:
        prefix, suffix = '', ''

    keys_set.add(key)

    if isinstance(value, str):
        values_set.add(f'{prefix}{value}{suffix}')
        keys_and_values_set.add((key, f'{prefix}{value}{suffix}'))
    elif isinstance(value, list):
        values_set.update({f'{prefix}{item}{suffix}' for item in value})
        keys_and_values_set.update((key, f'{prefix}{item}{suffix}') for item in value)


def extract_apis(detection: dict) -> tuple[set[str], set[str], set[str], set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    api_name_field_names, api_source_field_names = set(), set()
    api_names, api_sources = set(), set()
    api_name_field_names_and_api_names, api_source_field_names_and_api_sources = set(), set()

    for key, value in detection.items():
        if isinstance(value, dict):
            api_name_field_names_rec, api_source_field_names_rec, api_names_rec, api_sources_rec, api_name_field_names_and_api_names_rec, api_source_field_names_and_api_sources_rec = extract_apis(value)
            api_name_field_names.update(api_name_field_names_rec)
            api_source_field_names.update(api_source_field_names_rec)
            api_names.update(api_names_rec)
            api_sources.update(api_sources_rec)
            api_name_field_names_and_api_names.update(api_name_field_names_and_api_names_rec)
            api_source_field_names_and_api_sources.update(api_source_field_names_and_api_sources_rec)
            # recursive_events, recursive_sources = extract_apis(value)
            # api_names.update(recursive_events)
            # api_sources.update(recursive_sources)
        elif key.startswith('eventName'):
            add_to_sets(key, value, api_name_field_names, api_names, api_name_field_names_and_api_names)
        elif key.startswith('eventSource'):
            add_to_sets(key, value, api_source_field_names, api_sources, api_source_field_names_and_api_sources)
        # elif key.startswith('eventName') or key.startswith('eventSource'):
        #     relevant_set = api_names if key.startswith('eventName') else api_sources
        #     add_to_sets(key, value, relevant_set)

    # return api_names, api_sources
    return api_name_field_names, api_source_field_names, api_names, api_sources, api_name_field_names_and_api_names, api_source_field_names_and_api_sources


def extract_ioc(detection: dict) -> tuple[set[str], set[str], set[str], set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    ip_address_field_names, user_agent_field_names = set(), set()
    ip_addresses, user_agents = set(), set()
    ip_address_field_names_and_ip_addresses, user_agent_field_names_and_user_agents = set(), set()
    # ioc = set()

    for key, value in detection.items():
        if isinstance(value, dict):
            ip_address_field_names_rec, user_agent_field_names_rec, ip_addresses_rec, user_agents_rec, ip_address_field_names_and_ip_addresses_rec, user_agent_field_names_and_user_agents_rec = extract_ioc(value)
            ip_address_field_names.update(ip_address_field_names_rec)
            user_agent_field_names.update(user_agent_field_names_rec)
            ip_addresses.update(ip_addresses_rec)
            user_agents.update(user_agents_rec)
            ip_address_field_names_and_ip_addresses.update(ip_address_field_names_and_ip_addresses_rec)
            user_agent_field_names_and_user_agents.update(user_agent_field_names_and_user_agents_rec)
            # ioc.update(get_ioc(value))
        elif key.startswith('sourceIPAddress'):
            add_to_sets(key, value, ip_address_field_names, ip_addresses, ip_address_field_names_and_ip_addresses)
        elif key.startswith('userAgent'):
            add_to_sets(key, value, user_agent_field_names, user_agents, user_agent_field_names_and_user_agents)
        # elif key.startswith('sourceIPAddress') or key.startswith('userAgent'):
        #     add_to_sets(key, value, ioc)

    # return ioc
    return ip_address_field_names, user_agent_field_names, ip_addresses, user_agents, ip_address_field_names_and_ip_addresses, user_agent_field_names_and_user_agents


def extract_others(detection: dict) -> tuple[set[str], set[str], set[tuple[str, str]]]:
    other_field_names = set()
    others = set()
    other_field_names_and_others = set()

    for key, value in detection.items():
        if isinstance(value, dict):
            other_field_names_rec, others_rec, other_field_names_and_others_rec = extract_others(value)
            other_field_names.update(other_field_names_rec)
            others.update(others_rec)
            other_field_names_and_others.update(other_field_names_and_others_rec)
            # others.update(get_others(value))
        elif not key.startswith('eventName') and not key.startswith('eventSource') and not key.startswith('sourceIPAddress') and not key.startswith('userAgent') and not key.startswith('condition'):
            add_to_sets(key, value, other_field_names, others, other_field_names_and_others)
            # add_to_sets(key, value, others)

    # return others
    return other_field_names, others, other_field_names_and_others


# def compare_sigma_rules(ground_truth_rule: Dict, output_rule: Dict):
#     results = {}
#
#     # results["title_similarity"] = get_text_similarity(ground_truth_rule["title"], output_rule["title"])
#     # results["description_similarity"] = get_text_similarity(ground_truth_rule["description"], output_rule["description"])
#
#     ground_truth_tactics, ground_truth_techniques, ground_truth_subtechniques = get_ttps(ground_truth_rule['tags'])
#     output_tactics, output_techniques, output_subtechniques = get_ttps(output_rule['tags'])
#     results['tactic'], results['technique'], results['subtechnique'] = calculate_performance_metrics(ground_truth_tactics, output_tactics), calculate_performance_metrics(ground_truth_techniques, output_techniques), calculate_performance_metrics(ground_truth_subtechniques, output_subtechniques)
#
#     ground_truth_product, ground_truth_service = {ground_truth_rule['logsource']['product']}, {ground_truth_rule['logsource']['service']}
#     output_product, output_service = {output_rule['logsource']['product']}, {output_rule['logsource']['service']}
#     results['product'], results['service'] = calculate_performance_metrics(ground_truth_product, output_product), calculate_performance_metrics(ground_truth_service, output_service)
#
#     ground_truth_events, ground_truth_sources = get_api_calls(ground_truth_rule)
#     output_events, output_sources = get_api_calls(output_rule)
#     results['event'], results['source'] = calculate_performance_metrics(ground_truth_events, output_events), calculate_performance_metrics(ground_truth_sources, output_sources)
#
#     ground_truth_ioc = get_ioc(ground_truth_rule['detection'])
#     output_ioc = get_ioc(output_rule['detection'])
#     results['ioc'] = calculate_performance_metrics(ground_truth_ioc, output_ioc)
#
#     ground_truth_others = get_others(ground_truth_rule['detection'])
#     output_others = get_others(output_rule['detection'])
#     results['other'] = calculate_performance_metrics(ground_truth_others, output_others)
#
#     # TODO: Handle 'falsepositives' field
#
#     criticality_levels = {'informational': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5}
#     ground_truth_criticality = criticality_levels[ground_truth_rule['level']]
#     output_criticality = criticality_levels[output_rule['level']]
#     results['criticality'] = 1 + (output_criticality - ground_truth_criticality) * 0.25
#
#     return results


def extract_entities_and_relationships(rules: dict | list[dict]) -> tuple[dict[str, set[str]], dict[str, set[tuple[str, str]]]]:
    if isinstance(rules, dict):
        rules = [rules]

    entities = {
        'tactics': set(),
        'techniques': set(),
        'subtechniques': set(),
        'product_field_names': set(),
        'service_field_names': set(),
        'products': set(),
        'services': set(),
        'api_name_field_names': set(),
        'api_source_field_names': set(),
        'api_names': set(),
        'api_sources': set(),
        'ip_address_field_names': set(),
        'user_agent_field_names': set(),
        'ip_addresses': set(),
        'user_agents': set(),
        'other_field_names': set(),
        'others': set()
    }
    relationships = {
        'product_field_names_and_products': set(),
        'service_field_names_and_services': set(),
        'api_name_field_names_and_api_names': set(),
        'api_source_field_names_and_api_sources': set(),
        'ip_address_field_names_and_ip_addresses': set(),
        'user_agent_field_names_and_user_agents': set(),
        'other_field_names_and_others': set()
    }
    for rule in rules:
        tactics, techniques, subtechniques = get_ttps(rule['tags'])
        entities['tactics'].update(tactics)
        entities['techniques'].update(techniques)
        entities['subtechniques'].update(subtechniques)

        product_field_names, service_field_names, products, services, product_field_names_and_products, service_field_names_and_services = extract_logsource_data(rule['logsource'])
        entities['product_field_names'].update(product_field_names)
        entities['service_field_names'].update(service_field_names)
        entities['products'].update(products)
        entities['services'].update(services)
        relationships['product_field_names_and_products'].update(product_field_names_and_products)
        relationships['service_field_names_and_services'].update(service_field_names_and_services)

        api_name_field_names, api_source_field_names, api_names, api_sources, api_name_field_names_and_api_names, api_source_field_names_and_api_sources = extract_apis(rule['detection'])
        entities['api_name_field_names'].update(api_name_field_names)
        entities['api_source_field_names'].update(api_source_field_names)
        entities['api_names'].update(api_names)
        entities['api_sources'].update(api_sources)
        relationships['api_name_field_names_and_api_names'].update(api_name_field_names_and_api_names)
        relationships['api_source_field_names_and_api_sources'].update(api_source_field_names_and_api_sources)

        ip_address_field_names, user_agent_field_names, ip_addresses, user_agents, ip_address_field_names_and_ip_addresses, user_agent_field_names_and_user_agents = extract_ioc(rule['detection'])
        entities['ip_address_field_names'].update(ip_address_field_names)
        entities['user_agent_field_names'].update(user_agent_field_names)
        entities['ip_addresses'].update(ip_addresses)
        entities['user_agents'].update(user_agents)
        relationships['ip_address_field_names_and_ip_addresses'].update(ip_address_field_names_and_ip_addresses)
        relationships['user_agent_field_names_and_user_agents'].update(user_agent_field_names_and_user_agents)

        other_field_names, others, other_field_names_and_others = extract_others(rule['detection'])
        entities['other_field_names'].update(other_field_names)
        entities['others'].update(others)
        relationships['other_field_names_and_others'].update(other_field_names_and_others)

    return entities, relationships


def _get_latest_run_file_path(file: str) -> str:
    # get all the files in which their prefix is the same as the file
    directory_path = os.path.abspath('output')
    files = [f for f in os.listdir(directory_path) if f.startswith(f'{file}_(run_')]
    file = sorted(files, reverse=True)[0]
    file_path = os.path.join(directory_path, file)

    return file_path


def main(paths: list[str]):
#     ground_truth_rule = yaml.safe_load("""title: AWS IAM S3Browser Templated S3 Bucket Policy Creation
# id: db014773-7375-4f4e-b83b-133337c0ffee
# status: experimental
# description: Detects S3 Browser utility creating Inline IAM Policy containing default S3 bucket name placeholder value of <YOUR-BUCKET-NAME>.
# references:
#     - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
# author: daniel.bohannon@permiso.io (@danielhbohannon)
# date: 2023/05/17
# modified: 2023/05/17
# tags:
#     - attack.execution
#     - attack.t1059.009
#     - attack.persistence
#     - attack.t1078.004
# logsource:
#     product: aws
#     service: cloudtrail
# detection:
#     selection_source:
#         eventSource: iam.amazonaws.com
#         eventName: PutUserPolicy
#     filter_tooling:
#         userAgent|contains: 'S3 Browser'
#     filter_policy_resource:
#         requestParameters|contains: '"arn:aws:s3:::<YOUR-BUCKET-NAME>/*"'
#     filter_policy_action:
#         requestParameters|contains: '"s3:GetObject"'
#     filter_policy_effect:
#         requestParameters|contains: '"Allow"'
#     condition: selection_source and filter_tooling and filter_policy_resource and filter_policy_action and filter_policy_effect
# falsepositives:
#     - Valid usage of S3 Browser with accidental creation of default Inline IAM Policy without changing default S3 bucket name placeholder value
# level: high""")
#     output_rule = yaml.safe_load("""title: Suspicious IAM User Policy Creation
# status: experimental
# description: Detects creation of IAM user policies which may indicate malicious activity by threat actors such as GUI-vil who attempt persistence.
# references:
#     - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/
#     - https://attack.mitre.org/techniques/T1098/003/
# author: LLMCloudHunter
# date: 2024/05/17
# tags:
#     - attack.persistence
#     - attack.t1098
#     - attack.t1098.003
# logsource:
#     product: aws
#     service: cloudtrail
# detection:
#     selection:
#         eventSource: iam.amazonaws.com
#         eventName: PutUserPolicy
#     selection_ioc_ip:
#         sourceIPAddress:
#             - 114.125.246.235
#             - 182.1.229.252
#             - 114.125.228.81
#             - 114.125.232.189
#             - 114.125.246.43
#             - 114.125.245.53
#             - 36.85.110.142
#             - 114.125.229.197
#             - 114.125.247.101
#     selection_ioc_ua:
#         userAgent|contains: S3 Browser 9.5.5 https://s3browser.com/
# condition: selection and (selection_ioc_ip or selection_ioc_ua)
# falsepositives:
#     - Legitimate IAM user policy creation for administrative purposes
# level: high""")

    for file in files:
        latest_run_file_path = _get_latest_run_file_path(file)
        with open(latest_run_file_path, 'r') as f:
            output_rules = yaml.safe_load(f)
        output_entities, output_relationships = extract_entities_and_relationships(output_rules)


        with open(os.path.abspath(f'ground_truth\\rules\\{file}.yaml'), 'r') as f:
            ground_truth_rules = yaml.safe_load(f)

        # entities, relationships = extract_entities_and_relationships([ground_truth_rule, output_rule])
    # entities, relationships = extract_entities_and_relationships(ground_truth_rule)
    print('hi')

    # results = compare_sigma_rules(ground_truth_rule, output_rule)
    # for key, value in results.items():
    #     print(key, value)



    # print_entities(rule_objects_list)
    # print_entity_sigma_field(rule_objects_list)
    # print_api_call_tactic(rule_objects_list)
    # print_api_call_technique(rule_objects_list)
    # print_api_call_sub_technique(rule_objects_list)
    # print_api_call_ioc(rule_objects_list)
    # print_api_call_other(rule_objects_list)


if __name__ == "__main__":
    files = []
    # files.append('anatomy_of_attack_exposed_keys_to_crypto_mining')
    # files.append('behind_the_scenes_expel_soc_alert_aws')
    files.append('cloud_breach_terraform_data_theft')
    # files.append('compromised_cloud_compute_credentials_(case_1)')
    # files.append('detecting-ai-resource-hijacking-with-composite-alerts')
    # files.append('finding-evil-in-aws')
    # files.append('incident_report_from_cli_to_console_chasing_an_attacker_in_aws')
    # files.append('incident_report_stolen_aws_access_keys')
    # files.append('lucr_3_scattered_spider_getting_saas_y_in_the_cloud')
    # files.append('malicious_operations_of_exposed_iam_keys_cryptojacking')
    # files.append('ransomware_in_the_cloud')
    # files.append('shinyhunters-ransomware-extortion')
    # files.append('sugarcrm_cloud_incident_black_hat')
    # files.append('tales-from-the-cloud-trenches-aws-activity-to-phishing')
    # files.append('tales-from-the-cloud-trenches-ecs-crypto-mining')
    # files.append('tales-from-the-cloud-trenches-raiding-for-vaults-buckets-secrets')
    # files.append('the-curious-case-of-dangerdev-protonmail-me')
    # files.append('two_real_life_examples_of_why_limiting_permissions_works_lessons_from_aws_cirt_(case_1)')
    # files.append('two_real_life_examples_of_why_limiting_permissions_works_lessons_from_aws_cirt_(case_2)')
    # files.append('unmasking_guivil_new_cloud_threat_actor')

    main(files)
