from concurrent.futures import ThreadPoolExecutor, as_completed

from downloader import Downloader
from parser import Parser
from utils import setup_logging
from preprocessor import Preprocessor

ground_truth = {'https://permiso.io/blog/s/anatomy-of-attack-exposed-keys-to-crypto-mining/': 'anatomy_of_attack_exposed_keys_to_crypto_mining.txt',
                'https://expel.com/blog/behind-the-scenes-expel-soc-alert-aws/': 'behind_the_scenes_expel_soc_alert_aws.txt',
                'https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/': 'malicious_operations_of_exposed_iam_keys_cryptojacking.txt',
                'https://www.invictus-ir.com/news/ransomware-in-the-cloud/': 'ransomware_in_the_cloud.txt',
                'https://sysdig.com/blog/cloud-breach-terraform-data-theft/': 'cloud_breach_terraform_data_theft.txt',
                'https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/': 'compromised_cloud_compute_credentials.txt',
                'https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/': 'incident_report_from_cli_to_console_chasing_an_attacker_in_aws.txt',
                'https://expel.com/blog/incident-report-stolen-aws-access-keys/': 'incident_report_stolen_aws_access_keys.txt',
                'https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud/': 'lucr_3_scattered_spider_getting_saas_y_in_the_cloud.txt',
                'https://aws.amazon.com/blogs/security/two-real-life-examples-of-why-limiting-permissions-works-lessons-from-aws-cirt/': 'two_real_life_examples_of_why_limiting_permissions_works_lessons_from_aws_cirt.txt',
                'https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/': 'unmasking_guivil_new_cloud_threat_actor.txt',
                'https://unit42.paloaltonetworks.com/sugarcrm-cloud-incident-black-hat/': 'sugarcrm_cloud_incident_black_hat.txt'}

for url in list(ground_truth.keys()):
    with open(f'ground_truth/markdowns/{ground_truth[url]}', 'r', encoding="utf8") as f:
        ground_truth[url] = f.read()

setup_logging()
preprocessor = Preprocessor()


def check_url(url):
    html = Downloader.fetch_website(url)
    markdown, _ = Parser.parse_html(html)
    result = "OK" if markdown == ground_truth[url] else "FAIL"
    return f'{url}: {result}'


with ThreadPoolExecutor(max_workers=10) as executor:
    futures = {executor.submit(check_url, url): url for url in list(ground_truth.keys())}
    for future in as_completed(futures):
        print(future.result())
