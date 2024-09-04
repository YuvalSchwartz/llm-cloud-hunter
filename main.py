from dotenv import load_dotenv
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import setup_logging, dump_yaml
from llm_cloud_hunter import LLMCloudHunter


def main(urls: str | List[str]) -> None:
    setup_logging()
    load_dotenv()

    if isinstance(urls, str):
        urls = [urls]

    llm_cloud_hunter = LLMCloudHunter()

    url_to_rules = {}
    with ThreadPoolExecutor() as executor:
        future_to_url = {executor.submit(llm_cloud_hunter.process_url, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            rules = future.result()
            if rules:
                url_to_rules[url] = rules
                # TODO: Delete this line
                print(dump_yaml(rules))
            else:
                url_to_rules[url] = None


if __name__ == '__main__':
    urls = []
    urls.append('https://permiso.io/blog/s/anatomy-of-attack-exposed-keys-to-crypto-mining/')
    # urls.append('https://expel.com/blog/behind-the-scenes-expel-soc-alert-aws/')
    # urls.append('https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/')
    # urls.append('https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/')
    # urls.append('https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/')
    # urls.append('https://expel.com/blog/incident-report-stolen-aws-access-keys/')
    # urls.append('https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud/')
    # urls.append('https://www.invictus-ir.com/news/ransomware-in-the-cloud/')
    # urls.append('https://sysdig.com/blog/cloud-breach-terraform-data-theft/')
    # urls.append('https://aws.amazon.com/blogs/security/two-real-life-examples-of-why-limiting-permissions-works-lessons-from-aws-cirt/')
    # urls.append('https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/')
    # urls.append('https://unit42.paloaltonetworks.com/sugarcrm-cloud-incident-black-hat/')
    
    # NEW URLS:
    # urls.append('https://expel.com/blog/finding-evil-in-aws/')





    # urls.append('https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/')
    # urls.append('https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me')
    # urls.append('https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-raiding-for-vaults-buckets-secrets/')
    # urls.append('https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-aws-activity-to-phishing/')
    # urls.append('https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts')
    # urls.append('https://onecloudplease.com/blog/s3-bucket-namesquatting?utm_source=tldrsec.com&utm_medium=referral&utm_campaign=lesser-known-techniques-for-attacking-aws-environments')
    # urls.append('https://rhinosecuritylabs.com/aws/aws-role-enumeration-iam-p2/?utm_source=tldrsec.com&utm_medium=referral&utm_campaign=lesser-known-techniques-for-attacking-aws-environments')
    # urls.append('https://summitroute.com/blog/2019/02/04/lateral_movement_abusing_trust/?utm_source=tldrsec.com&utm_medium=referral&utm_campaign=lesser-known-techniques-for-attacking-aws-environments')
    # urls.append('https://rhinosecuritylabs.com/aws/assume-worst-aws-assume-role-enumeration/?utm_source=tldrsec.com&utm_medium=referral&utm_campaign=lesser-known-techniques-for-attacking-aws-environments')

    main(urls)
