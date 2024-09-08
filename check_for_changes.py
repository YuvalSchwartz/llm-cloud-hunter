from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import setup_logging
from preprocessor import Preprocessor

url_to_file = {'https://permiso.io/blog/s/anatomy-of-attack-exposed-keys-to-crypto-mining/': ['anatomy_of_attack_exposed_keys_to_crypto_mining.txt'],
               'https://expel.com/blog/behind-the-scenes-expel-soc-alert-aws/': ['behind_the_scenes_expel_soc_alert_aws.txt'],
               'https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/': ['malicious_operations_of_exposed_iam_keys_cryptojacking.txt'],
               'https://www.invictus-ir.com/news/ransomware-in-the-cloud/': ['ransomware_in_the_cloud.txt'],
               'https://sysdig.com/blog/cloud-breach-terraform-data-theft/': ['cloud_breach_terraform_data_theft.txt'],
               'https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/': ['compromised_cloud_compute_credentials_(case_1).txt', None],
               'https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/': ['incident_report_from_cli_to_console_chasing_an_attacker_in_aws.txt'],
               'https://expel.com/blog/incident-report-stolen-aws-access-keys/': ['incident_report_stolen_aws_access_keys.txt'],
               'https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud/': ['lucr_3_scattered_spider_getting_saas_y_in_the_cloud.txt'],
               'https://aws.amazon.com/blogs/security/two-real-life-examples-of-why-limiting-permissions-works-lessons-from-aws-cirt/': ['two_real_life_examples_of_why_limiting_permissions_works_lessons_from_aws_cirt_(case_1).txt', 'two_real_life_examples_of_why_limiting_permissions_works_lessons_from_aws_cirt_(case_2).txt'],
               'https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/': ['unmasking_guivil_new_cloud_threat_actor.txt'],
               'https://unit42.paloaltonetworks.com/sugarcrm-cloud-incident-black-hat/': ['sugarcrm_cloud_incident_black_hat.txt'],
               'https://expel.com/blog/finding-evil-in-aws/': ['finding-evil-in-aws.txt'],
               'https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/': ['tales-from-the-cloud-trenches-ecs-crypto-mining.txt'],
               'https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me': ['the-curious-case-of-dangerdev-protonmail-me.txt'],
               'https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-raiding-for-vaults-buckets-secrets/': ['tales-from-the-cloud-trenches-raiding-for-vaults-buckets-secrets.txt'],
               'https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-aws-activity-to-phishing/': ['tales-from-the-cloud-trenches-aws-activity-to-phishing.txt'],
               'https://unit42.paloaltonetworks.com/shinyhunters-ransomware-extortion/': ['shinyhunters-ransomware-extortion.txt'],
               'https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts': ['detecting-ai-resource-hijacking-with-composite-alerts.txt']}

ground_truth = {}
for url in url_to_file:
    ground_truth[url] = []
    for file in url_to_file[url]:
        if file is not None:
            with open(f'ground_truth/markdowns/{file}', 'r', encoding="utf8") as f:
                ground_truth[url].append(f.read())
        else:
            ground_truth[url].append(None)

setup_logging()
preprocessor = Preprocessor()


def check_url(url):
    attack_cases = Preprocessor().preprocess_oscti(url, include_images=True)
    result = []
    for i, attack_case in enumerate(attack_cases):
        if attack_case is not None:
            markdown = attack_case[0]
            if len(attack_cases) == 1:
                result.append("OK" if markdown == ground_truth[url][0] else f'{url}: FAIL')
            else:
                result.append("OK" if markdown == ground_truth[url][i] else f'{url} (Case {i + 1}): FAIL')
    return result


with ThreadPoolExecutor(max_workers=10) as executor:
    futures = {executor.submit(check_url, url): url for url in list(ground_truth.keys())}
    for future in as_completed(futures):
        result = future.result()
        for r in result:
            print(r)
