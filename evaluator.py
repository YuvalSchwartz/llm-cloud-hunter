import os
import re
import subprocess
import yaml

from utils import tactic_name_to_id, technique_id_to_name, technique_id_to_subtechnique_id_to_name


def _get_latest_run_file_path(file_prefix: str) -> str:
    directory_path = os.path.abspath('output')
    files = [f for f in os.listdir(directory_path) if f.startswith(f'{file_prefix}_(run_')]
    file = sorted(files, reverse=True)[0]
    file_path = os.path.join(directory_path, file)

    return file_path


def _get_ttps(tags: list[str]) -> tuple[set[str], set[str], set[str]]:
    tactics, techniques, subtechniques = set(), set(), set()

    for tag in tags:
        tag = tag.replace('attack.', '')
        if not tag.startswith('t'):
            tag = tag.replace('_', ' ').title()
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


def _extract_logsource_data(logsource: dict) -> tuple[set[str], set[str], set[str], set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    product_field_names, service_field_names = set(), set()
    products, services = set(), set()
    product_field_names_and_products, service_field_names_and_services = set(), set()

    for key, value in logsource.items():
        if key == 'product':
            _add_to_sets(key, value, product_field_names, products, product_field_names_and_products)
        elif key == 'service':
            _add_to_sets(key, value, service_field_names, services, service_field_names_and_services)

    return product_field_names, service_field_names, products, services, product_field_names_and_products, service_field_names_and_services


def _add_to_sets(key: str, value: str | list[str], keys_set: set[str], values_set: set[str], keys_and_values_set: set[tuple[str, str]]) -> None:
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


def _extract_apis(detection: dict) -> tuple[set[str], set[str], set[str], set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    api_name_field_names, api_source_field_names = set(), set()
    api_names, api_sources = set(), set()
    api_name_field_names_and_api_names, api_source_field_names_and_api_sources = set(), set()

    for key, value in detection.items():
        if isinstance(value, dict):
            api_name_field_names_rec, api_source_field_names_rec, api_names_rec, api_sources_rec, api_name_field_names_and_api_names_rec, api_source_field_names_and_api_sources_rec = _extract_apis(value)
            api_name_field_names.update(api_name_field_names_rec)
            api_source_field_names.update(api_source_field_names_rec)
            api_names.update(api_names_rec)
            api_sources.update(api_sources_rec)
            api_name_field_names_and_api_names.update(api_name_field_names_and_api_names_rec)
            api_source_field_names_and_api_sources.update(api_source_field_names_and_api_sources_rec)
        elif key.startswith('eventName'):
            _add_to_sets(key, value, api_name_field_names, api_names, api_name_field_names_and_api_names)
        elif key.startswith('eventSource'):
            _add_to_sets(key, value, api_source_field_names, api_sources, api_source_field_names_and_api_sources)

    return api_name_field_names, api_source_field_names, api_names, api_sources, api_name_field_names_and_api_names, api_source_field_names_and_api_sources


def _extract_ioc(detection: dict) -> tuple[set[str], set[str], set[str], set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    ip_address_field_names, user_agent_field_names = set(), set()
    ip_addresses, user_agents = set(), set()
    ip_address_field_names_and_ip_addresses, user_agent_field_names_and_user_agents = set(), set()

    for key, value in detection.items():
        if isinstance(value, dict):
            ip_address_field_names_rec, user_agent_field_names_rec, ip_addresses_rec, user_agents_rec, ip_address_field_names_and_ip_addresses_rec, user_agent_field_names_and_user_agents_rec = _extract_ioc(value)
            ip_address_field_names.update(ip_address_field_names_rec)
            user_agent_field_names.update(user_agent_field_names_rec)
            ip_addresses.update(ip_addresses_rec)
            user_agents.update(user_agents_rec)
            ip_address_field_names_and_ip_addresses.update(ip_address_field_names_and_ip_addresses_rec)
            user_agent_field_names_and_user_agents.update(user_agent_field_names_and_user_agents_rec)
        elif key.startswith('sourceIPAddress'):
            _add_to_sets(key, value, ip_address_field_names, ip_addresses, ip_address_field_names_and_ip_addresses)
        elif key.startswith('userAgent'):
            _add_to_sets(key, value, user_agent_field_names, user_agents, user_agent_field_names_and_user_agents)

    # return ioc
    return ip_address_field_names, user_agent_field_names, ip_addresses, user_agents, ip_address_field_names_and_ip_addresses, user_agent_field_names_and_user_agents


def _extract_others(detection: dict) -> tuple[set[str], set[str], set[tuple[str, str]]]:
    other_field_names = set()
    others = set()
    other_field_names_and_others = set()

    for key, value in detection.items():
        if isinstance(value, dict):
            other_field_names_rec, others_rec, other_field_names_and_others_rec = _extract_others(value)
            other_field_names.update(other_field_names_rec)
            others.update(others_rec)
            other_field_names_and_others.update(other_field_names_and_others_rec)
        elif not key.startswith('eventName') and not key.startswith('eventSource') and not key.startswith('sourceIPAddress') and not key.startswith('userAgent') and not key.startswith('condition'):
            _add_to_sets(key, value, other_field_names, others, other_field_names_and_others)

    return other_field_names, others, other_field_names_and_others


def _extract_entities_and_relationships(rules: dict | list[dict]) -> tuple[dict[str, set[str]], dict[str, set[tuple[str, str]]]]:
    if isinstance(rules, dict):
        rules = [rules]

    entities = {
        'tactic': set(),
        'technique': set(),
        'subtechnique': set(),
        'product_field_name': set(),
        'service_field_name': set(),
        'product': set(),
        'service': set(),
        'api_name_field_name': set(),
        'api_source_field_name': set(),
        'api_name': set(),
        'api_source': set(),
        'ip_address_field_name': set(),
        'user_agent_field_name': set(),
        'ip_address': set(),
        'user_agent': set(),
        'other_field_name': set(),
        'other': set()
    }
    relationships = {
        'product_field_name_and_product': set(),
        'service_field_name_and_service': set(),
        'api_name_field_name_and_api_name': set(),
        'api_source_field_name_and_api_source': set(),
        'ip_address_field_name_and_ip_address': set(),
        'user_agent_field_name_and_user_agent': set(),
        'other_field_name_and_other': set(),
        'api_name_and_tactic': set(),
        'api_name_and_technique': set(),
        'api_name_and_subtechnique': set(),
        'api_name_and_product': set(),
        'api_name_and_service': set(),
        'api_name_and_api_source': set(),
        'api_name_and_ip_address': set(),
        'api_name_and_user_agent': set(),
        'api_name_and_other': set()
    }
    for rule in rules:
        tactics, techniques, subtechniques = _get_ttps(rule['tags'])
        entities['tactic'].update(tactics)
        entities['technique'].update(techniques)
        entities['subtechnique'].update(subtechniques)

        product_field_names, service_field_names, products, services, product_field_names_and_products, service_field_names_and_services = _extract_logsource_data(rule['logsource'])
        entities['product_field_name'].update(product_field_names)
        entities['service_field_name'].update(service_field_names)
        entities['product'].update(products)
        entities['service'].update(services)
        relationships['product_field_name_and_product'].update(product_field_names_and_products)
        relationships['service_field_name_and_service'].update(service_field_names_and_services)

        api_name_field_names, api_source_field_names, api_names, api_sources, api_name_field_names_and_api_names, api_source_field_names_and_api_sources = _extract_apis(rule['detection'])
        entities['api_name_field_name'].update(api_name_field_names)
        entities['api_source_field_name'].update(api_source_field_names)
        entities['api_name'].update(api_names)
        entities['api_source'].update(api_sources)
        relationships['api_name_field_name_and_api_name'].update(api_name_field_names_and_api_names)
        relationships['api_source_field_name_and_api_source'].update(api_source_field_names_and_api_sources)

        ip_address_field_names, user_agent_field_names, ip_addresses, user_agents, ip_address_field_names_and_ip_addresses, user_agent_field_names_and_user_agents = _extract_ioc(rule['detection'])
        entities['ip_address_field_name'].update(ip_address_field_names)
        entities['user_agent_field_name'].update(user_agent_field_names)
        entities['ip_address'].update(ip_addresses)
        entities['user_agent'].update(user_agents)
        relationships['ip_address_field_name_and_ip_address'].update(ip_address_field_names_and_ip_addresses)
        relationships['user_agent_field_name_and_user_agent'].update(user_agent_field_names_and_user_agents)

        other_field_names, others, other_field_names_and_others = _extract_others(rule['detection'])
        entities['other_field_name'].update(other_field_names)
        entities['other'].update(others)
        relationships['other_field_name_and_other'].update(other_field_names_and_others)

        relationships['api_name_and_tactic'].update(set((api_name, tactic) for api_name in api_names for tactic in tactics))
        relationships['api_name_and_technique'].update(set((api_name, technique) for api_name in api_names for technique in techniques))
        relationships['api_name_and_subtechnique'].update(set((api_name, subtechnique) for api_name in api_names for subtechnique in subtechniques))
        relationships['api_name_and_product'].update(set((api_name, product) for api_name in api_names for product in products))
        relationships['api_name_and_service'].update(set((api_name, service) for api_name in api_names for service in services))
        relationships['api_name_and_api_source'].update(set((api_name, api_source) for api_name in api_names for api_source in api_sources))
        relationships['api_name_and_ip_address'].update(set((api_name, ip_address) for api_name in api_names for ip_address in ip_addresses))
        relationships['api_name_and_user_agent'].update(set((api_name, user_agent) for api_name in api_names for user_agent in user_agents))
        relationships['api_name_and_other'].update(set((api_name, other) for api_name in api_names for other in others))

    return entities, relationships


def _aggregate_entities_and_relationships(entities: dict[str, set[str]], relationships: dict[str, set[tuple[str, str]]]) -> None:
    entities['detection_field_name'] = set()
    for key in ['product_field_name', 'service_field_name', 'api_name_field_name', 'api_source_field_name', 'ip_address_field_name', 'user_agent_field_name', 'other_field_name']:
        entities['detection_field_name'].update(entities[key])
        del entities[key]

    entities['log_source'] = set()
    for key in ['product', 'service']:
        entities['log_source'].update(entities[key])
        del entities[key]

    entities['api_call'] = set()
    for key in ['api_name', 'api_source']:
        entities['api_call'].update(entities[key])
        del entities[key]

    entities['ioc'] = set()
    for key in ['ip_address', 'user_agent']:
        entities['ioc'].update(entities[key])
        del entities[key]

    entities['other'] = entities.pop('other')

    relationships['detection_field_name_and_detection_entity'] = set()
    for key in ['product_field_name_and_product', 'service_field_name_and_service', 'api_name_field_name_and_api_name', 'api_source_field_name_and_api_source', 'ip_address_field_name_and_ip_address', 'user_agent_field_name_and_user_agent', 'other_field_name_and_other']:
        relationships['detection_field_name_and_detection_entity'].update(relationships[key])
        del relationships[key]

    relationships['api_name_and_api_source'] = relationships.pop('api_name_and_api_source')

    relationships['api_name_and_log_source'] = set()
    for key in ['api_name_and_product', 'api_name_and_service']:
        relationships['api_name_and_log_source'].update(relationships[key])
        del relationships[key]

    relationships['api_name_and_ioc'] = set()
    for key in ['api_name_and_ip_address', 'api_name_and_user_agent']:
        relationships['api_name_and_ioc'].update(relationships[key])
        del relationships[key]

    relationships['api_name_and_other'] = relationships.pop('api_name_and_other')


def _filter_output_relationships(ground_truth_type_to_relationships: dict[str, set[tuple[str, str]]], output_type_to_relationships: dict[str, set[tuple[str, str]]]) -> dict[str, set[tuple[str, str]]]:
    for type, ground_truth_relationships in ground_truth_type_to_relationships.items():
        ground_truth_relationship_entities = {entity for relationship in ground_truth_relationships for entity in relationship}
        output_type_to_relationships[type] = {relationship for relationship in output_type_to_relationships[type] if all(entity in ground_truth_relationship_entities for entity in relationship)}

    return output_type_to_relationships


def _match_special_string(special_string: str, candidate: str) -> bool:
    # Convert special string to regex
    pattern = re.escape(special_string).replace(r'\*', '.*')
    # Add start and end anchors to ensure full string match
    pattern = f'^{pattern}$'
    # Check if candidate matches the pattern
    return re.match(pattern, candidate) is not None


def _compare_data(ground_truth_data: set[str] | set[tuple[str, str]], output_data: set[str] | set[tuple[str, str]]) -> tuple[float, float, float]:
    TP = 0
    FN = 0

    # Mark which items have been matched
    matched_output = set()

    # Calculate TP and FN
    for ground_truth_item in ground_truth_data:
        match_found = False
        for output_item in output_data:
            ground_truth_item = ground_truth_item if isinstance(ground_truth_item, str) else tuple(ground_truth_item)
            output_item = output_item if isinstance(output_item, str) else tuple(output_item)
            if all(_match_special_string(ground_truth_item_part, output_item_part) for ground_truth_item_part, output_item_part in zip(ground_truth_item, output_item)):
                TP += 1
                matched_output.add(output_item)
                match_found = True
                break
        if not match_found:
            FN += 1

    # Calculate FP (output items that were not matched with ground truth)
    FP = len(output_data - matched_output)

    precision = TP / (TP + FP) if (TP + FP) > 0 else float(1) if len(ground_truth_data) == 0 and len(output_data) == 0 else float(0)
    recall = TP / (TP + FN) if (TP + FN) > 0 else float(1) if len(ground_truth_data) == 0 and len(output_data) == 0 else float(0)
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else float(0)

    return precision, recall, f1_score


def _calculate_performance_metrics(ground_truth_type_to_data: dict[str, set[str] | set[tuple[str, str]]], output_type_to_data: dict[str, set[str] | set[tuple[str, str]]]) -> dict[str, tuple[int, tuple[float, float, float]]]:
    performance_metrics = {}
    for type, ground_truth_data in ground_truth_type_to_data.items():
        performance_metrics[type] = (len(ground_truth_data), _compare_data(ground_truth_data, output_type_to_data[type]))

    return performance_metrics


def _convert_to_splunk(rule: dict) -> bool:
    # Write the Sigma rule to a temporary YAML file
    temporary_rule_path = os.path.join(os.path.abspath('.'), 'temporary_rule.yaml')
    with open(temporary_rule_path, 'w') as temporary_file:
        yaml.safe_dump(rule, temporary_file)

    # Command to convert the Sigma rule to Splunk query using sigma-cli
    cmd = f'sigma convert --target splunk --pipeline splunk_windows {temporary_rule_path}'

    try:
        # Run the command
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return True
        else:
            return False
    finally:
        # Clean up temporary file
        os.remove(temporary_rule_path)


def main(file_prefixes: list[str]):
    entities_excel_output = ''
    relationships_excel_output = ''
    number_of_rules = 0
    number_of_compiled_rules = 0

    for file_prefix in file_prefixes:
        with open(os.path.abspath(f'ground_truth\\rules\\{file_prefix}.yaml'), 'r') as f:
            ground_truth_rules = yaml.safe_load(f)
        ground_truth_entities, ground_truth_relationships = _extract_entities_and_relationships(ground_truth_rules)
        _aggregate_entities_and_relationships(ground_truth_entities, ground_truth_relationships)

        latest_run_file_path = _get_latest_run_file_path(file_prefix)
        with open(latest_run_file_path, 'r') as f:
            output_rules = yaml.safe_load(f)
        output_entities, output_relationships = _extract_entities_and_relationships(output_rules)
        _aggregate_entities_and_relationships(output_entities, output_relationships)

        entity_metrics = _calculate_performance_metrics(ground_truth_entities, output_entities)
        for type, (support, metrics) in entity_metrics.items():
            entities_excel_output += f'{support},{metrics[0]:.2f},{metrics[1]:.2f},{metrics[2]:.2f},'
        entities_excel_output = entities_excel_output[:-1] + '\n'

        output_relationships = _filter_output_relationships(ground_truth_relationships, output_relationships)
        relationship_metrics = _calculate_performance_metrics(ground_truth_relationships, output_relationships)
        for type, (support, metrics) in relationship_metrics.items():
            relationships_excel_output += f'{support},{metrics[0]:.2f},{metrics[1]:.2f},{metrics[2]:.2f},'
        relationships_excel_output = relationships_excel_output[:-1] + '\n'

        if isinstance(output_rules, dict):
            output_rules = [output_rules]
        for output_rule in output_rules:
            number_of_rules += 1
            if _convert_to_splunk(output_rule):
                number_of_compiled_rules += 1

    print(f'Number of rules: {number_of_rules}, Number of compiled rules: {number_of_compiled_rules} ({number_of_compiled_rules / number_of_rules * 100:.2f}%)\n')
    print(f'Entities:\n{entities_excel_output[:-1]}\n')
    print(f'Relationships:\n{relationships_excel_output[:-1]}')


if __name__ == "__main__":
    file_prefixes = []
    # file_prefixes.append('anatomy_of_attack_exposed_keys_to_crypto_mining')
    # file_prefixes.append('behind_the_scenes_expel_soc_alert_aws')
    # file_prefixes.append('cloud_breach_terraform_data_theft')
    # file_prefixes.append('compromised_cloud_compute_credentials_(case_1)')
    # file_prefixes.append('finding_evil_in_aws')
    # file_prefixes.append('detecting_ai_resource_hijacking_with_composite_alerts')
    # file_prefixes.append('incident_report_from_cli_to_console_chasing_an_attacker_in_aws')
    # file_prefixes.append('incident_report_stolen_aws_access_keys')
    # file_prefixes.append('lucr_3_scattered_spider_getting_saas_y_in_the_cloud')
    # file_prefixes.append('malicious_operations_of_exposed_iam_keys_cryptojacking')
    # file_prefixes.append('ranso mware_in_the_cloud')
    # file_prefixes.append('shinyhunters_ransomware_extortion')
    # file_prefixes.append('sugarcrm_cloud_incident_black_hat')
    # file_prefixes.append('tales_from_the_cloud_trenches_aws_activity_to_phishing')
    # file_prefixes.append('tales_from_the_cloud_trenches_ecs_crypto_mining')
    # file_prefixes.append('tales_from_the_cloud_trenches_raiding_for_vaults_buckets_secrets')
    # file_prefixes.append('the_curious_case_of_dangerdev_protonmail_me')
    # file_prefixes.append('two_real_life_examples_of_why_limiting_permissions_works_lessons_from_aws_cirt_(case_1)')
    # file_prefixes.append('two_real_life_examples_of_why_limiting_permissions_works_lessons_from_aws_cirt_(case_2)')
    # file_prefixes.append('unmasking_guivil_new_cloud_threat_actor')

    main(file_prefixes)
