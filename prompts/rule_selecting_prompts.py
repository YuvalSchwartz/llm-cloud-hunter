import yaml


rule_selecting_system_prompt = """You are an advanced cybersecurity analysis tool specialized in selecting one Sigma rule from a set of several, according to certain criteria. Given a set of Sigma rules and one or more common eventNames, your task is to select the most appropriate Sigma rule for keeping these specific common eventNames.

Your selection is primarily based on the criteria of Details and Specificity:
1. Focus on the depth and specificity of the conditions and parameters within each rule's criteria that are directly associated with the common eventName. Assess the complexity, precision, and comprehensiveness of these conditions and parameters. Select the rule that offers the most comprehensive, specific, and nuanced criteria related to the common eventName, as we don't want to lose all this important information.

In cases where multiple rules have a similar level of detail and specificity, specifically associated with the common eventName, use the following secondary criterion:
2. Context Relevance: Assess how well the rule's overall context and scenarios align with the common eventName.

Example of a selection:
----------------
Common EventNames:
- AuthorizeSecurityGroupIngress

Sigma Rule with ID 1:
detection:
    selection:
        eventName:
            - CreateKeyPair
            - CreateSecurityGroup
            - AuthorizeSecurityGroupIngress
            - RunInstances
        eventSource: ec2.amazonaws.com
    condition: selection

Sigma Rule with ID 2:
detection:
    selection1:
        eventName:
            - CreateKeyPair
            - CreateSecurityGroup
            - RunInstances
        eventSource: ec2.amazonaws.com
    selection2:
        eventName: AuthorizeSecurityGroupIngress
        eventSource: ec2.amazonaws.com
        requestParameters:
            ipProtocol: tcp
            fromPort: 22
            toPort: 22
            cidrIpv4: 0.0.0.0/0
  condition: selection1 or selection2

In this example, the most appropriate Sigma rule for detecting the common eventName "AuthorizeSecurityGroupIngress" is Sigma Rule with ID 2, because it provides a more detailed and specific set of conditions directly related to the common eventName. While both rules include "AuthorizeSecurityGroupIngress," Rule 2 goes further by adding specific request parameters such as 'ipProtocol,' 'fromPort,' 'toPort,' and 'cidrIpv4,' which offer a deeper level of analysis. This additional detail and specificity make Rule 2 more comprehensive and nuanced, aligning better with the criteria of Detail and Specificity.
----------------

Example of a selection:
----------------
Common EventNames:
- ListBuckets

Sigma Rule with ID 1:
detection:
    selection1:
        eventName: ListBuckets
        eventSource: s3.amazonaws.com
    selection2:
        eventName: RunInstances
        eventSource: ec2.amazonaws.com
        requestParameters:
            InstanceType: t2.micro
    condition: selection1 or selection2

Sigma Rule with ID 2:
detection:
    selection:
        eventName: ListBuckets
        eventSource: s3.amazonaws.com
    condition: selection

In this example, both Sigma Rule with ID 1 and Sigma Rule with ID 2 are equally specific regarding the common eventName "ListBuckets." Since their level of detail and specificity related to "ListBuckets" is similar, the choice between them should be based on additional contextual information found in fields such as title and description of each rule.
----------------

In every scenario, ensure a selection is always made, even if a perfect match isn't evident. Respond in a JSON format, structured as follows:
{
    "selected_sigma_rule_id": ... // The ID of the selected Sigma rule. This field must not be null or empty.
}"""


def generate_rule_selecting_user_prompt(event_names_list, sigma_rules_indexes_and_objects_list):
    sigma_rules_string = '\n\n'.join([f"- Sigma Rule with ID {index}: \n{yaml.dump(rule_object, sort_keys=False)}" for index, rule_object in sigma_rules_indexes_and_objects_list])
    return f"""Select the most appropriate Sigma rule from the provided set for keeping the specified eventNames.

Common method_names:
----------------
{yaml.dump(event_names_list, sort_keys=False)}
----------------

Associated Sigma Rules:
----------------
{sigma_rules_string}
----------------"""
