from typing import Dict, List
from datetime import date
import logging

from preprocessor import Preprocessor
from paragraph_level_processor import ParagraphLevelProcessor
from oscti_level_processor import OSCTILevelProcessor


class LLMCloudHunter:
    def __init__(self, preprocessor: Preprocessor = None, paragraph_level_processor: ParagraphLevelProcessor = None, oscti_level_processor: OSCTILevelProcessor = None):
        self.preprocessor = preprocessor if preprocessor else Preprocessor()
        self.paragraph_level_processor = paragraph_level_processor if paragraph_level_processor else ParagraphLevelProcessor()
        self.oscti_level_processor = oscti_level_processor if oscti_level_processor else OSCTILevelProcessor()

    @staticmethod
    def _add_metadata(rules: Dict | List[Dict], reference: str) -> Dict | List[Dict]:
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

    def process_url(self, url: str) -> Dict | List[Dict]:
        logging.info(f'Processing {url}')
        logging.info(f'\tPreprocessing OSCTI')
        markdown, paragraphs = self.preprocessor.preprocess_oscti(url)
        logging.info(f'\tProcessing paragraphs')
        rules = self.paragraph_level_processor.process_paragraphs(paragraphs)
        logging.info(f'\tProcessing rules')
        rules = self.oscti_level_processor.process_rules(rules, markdown)
        rules = self._add_metadata(rules, url)

        return rules
