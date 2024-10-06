import os
import time
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import setup_logging, dump_yaml
from llm_cloud_hunter import LLMCloudHunter


def _get_file_path(directory_path: str, url: str, case_number: int | None) -> str:
    url = url if url.endswith('/') else url + '/'
    base_name = url.split('/')[-2].lower().replace('-', '_')
    case_name = base_name if case_number is None else f'{base_name}_(case_{case_number})'
    run_number = 1
    while True:
        run_name = f'{case_name}_(run_{run_number}).yaml'
        run_path = os.path.join(directory_path, run_name)
        if not os.path.exists(run_path):
            return run_path
        run_number += 1


def _write_output(url: str, case_number: int | None, rules: dict | list[dict]) -> None:
    directory_path = os.path.abspath('output')
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

    file_path = _get_file_path(directory_path, url, case_number)

    with open(file_path, 'w') as f:
        f.write(dump_yaml(rules))


def main(urls: str | list[str]) -> None:
    setup_logging()
    load_dotenv()

    if isinstance(urls, str):
        urls = [urls]

    llm_cloud_hunter = LLMCloudHunter()

    with ThreadPoolExecutor() as executor:
        future_to_url = {executor.submit(llm_cloud_hunter.process_url, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            attack_cases = future.result()
            for rules, case_number in attack_cases:
                _write_output(url, case_number, rules)


if __name__ == '__main__':
    urls = []
    #####   Done and have ground truth    #####

    # Done by Yuval
    # urls.append('https://permiso.io/blog/s/anatomy-of-attack-exposed-keys-to-crypto-mining/')
    # urls.append('https://expel.com/blog/behind-the-scenes-expel-soc-alert-aws/')
    # urls.append('https://sysdig.com/blog/cloud-breach-terraform-data-theft/')

    #Done by Lavi
    # urls.append('https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/')
    # urls.append('https://expel.com/blog/finding-evil-in-aws/')
    # urls.append('https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts/')
    # urls.append('https://aws.amazon.com/blogs/security/two-real-life-examples-of-why-limiting-permissions-works-lessons-from-aws-cirt/')
    # urls.append('https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me/')
    # urls.append('https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/')
    # urls.append('https://expel.com/blog/incident-report-stolen-aws-access-keys/')
    # urls.append('https://unit42.paloaltonetworks.com/sugarcrm-cloud-incident-black-hat/')
    # urls.append('https://www.invictus-ir.com/news/ransomware-in-the-cloud/')
    # urls.append('https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud/')
    # urls.append('https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/')
    # urls.append('https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-aws-activity-to-phishing/')
    # urls.append('https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/')
    # urls.append('https://unit42.paloaltonetworks.com/shinyhunters-ransomware-extortion/')

    #####   Done but need ground truth  #####


    # Need to run

    # not working...
    #   error: in _process_paragraph KeyError: 's'
    urls.append('https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-raiding-for-vaults-buckets-secrets/')
    urls.append('https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/')


    start_time = time.time()
    main(urls)
    end_time = time.time()
    minutes = int((end_time - start_time) / 60)
    seconds = round((end_time - start_time) - (minutes * 60))
    print(f'Total time taken: {minutes:02d}:{seconds:02d}')
