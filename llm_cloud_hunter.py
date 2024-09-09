from datetime import date
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from preprocessor import Preprocessor
from paragraph_level_processor import ParagraphLevelProcessor
from oscti_level_processor import OSCTILevelProcessor


class LLMCloudHunter:
    def __init__(self, preprocessor: Preprocessor = None, paragraph_level_processor: ParagraphLevelProcessor = None, oscti_level_processor: OSCTILevelProcessor = None):
        self.preprocessor = preprocessor if preprocessor else Preprocessor()
        self.paragraph_level_processor = paragraph_level_processor if paragraph_level_processor else ParagraphLevelProcessor()
        self.oscti_level_processor = oscti_level_processor if oscti_level_processor else OSCTILevelProcessor()

    @staticmethod
    def _add_metadata(rules: dict | list[dict], reference: str) -> dict | list[dict]:
        if isinstance(rules, dict):
            rules = [rules]

        for i in range(len(rules)):
            rule_items = list(rules[i].items())

            title_index = next(index for index, (key, value) in enumerate(rule_items) if key == 'title')
            rule_items.insert(title_index + 1, ('status', 'experimental'))

            description_index = next(index for index, (key, value) in enumerate(rule_items) if key == 'description')
            rule_items.insert(description_index + 1, ('references', [reference]))

            references_index = next(index for index, (key, value) in enumerate(rule_items) if key == 'references')
            rule_items.insert(references_index + 1, ('author', 'LLMCloudHunter'))

            current_date = date.today().strftime("%Y/%m/%d")
            author_index = next(index for index, (key, value) in enumerate(rule_items) if key == 'author')
            rule_items.insert(author_index + 1, ('date', current_date))

            rules[i] = dict(rule_items)

        if len(rules) == 1:
            return rules[0]

        return rules

    def _process_attack_case(self, url: str, markdown: str, paragraphs: list[str]) -> dict | list[dict]:
        logging.info(f'\tProcessing paragraphs')
        rules = self.paragraph_level_processor.process_paragraphs(paragraphs)
        logging.info(f'\tProcessing rules')
        rules = self.oscti_level_processor.process_rules(rules, markdown)
        logging.info(f'\tAdding metadata to rules')
        rules = self._add_metadata(rules, url)

        return rules

    def process_url(self, url: str) -> list[tuple[dict | list[dict], int | None]]:
        result = []
        logging.info(f'Processing {url}')
        logging.info(f'\tPreprocessing OSCTI')
        attack_cases = self.preprocessor.preprocess_oscti(url)

        with ThreadPoolExecutor() as executor:
            future_to_attack_case = {executor.submit(self._process_attack_case, url, attack_case[0], attack_case[1]): case_index for case_index, attack_case in enumerate(attack_cases) if attack_case is not None}
            for future in as_completed(future_to_attack_case):
                case_number = future_to_attack_case[future] + 1 if len(attack_cases) > 1 else None
                rules = future.result()
                result.append((rules, case_number))

        return result
