import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from downloader import Downloader
from parser import Parser
from image_analyzer import ImageAnalyzer


class Preprocessor:
    def __init__(self, image_analyzer: ImageAnalyzer = None):
        self.image_analyzer = image_analyzer if image_analyzer else ImageAnalyzer()

    @staticmethod
    def _split_to_paragraphs(markdown: str) -> list[tuple[str, int]]:
        lines = markdown.split('\n')
        paragraphs_and_levels = []
        inside_paragraph = False
        current_paragraph_content = ""

        for line in lines:
            if line.startswith('#'):
                if current_paragraph_content:
                    paragraphs_and_levels.append((current_paragraph_content.strip(), len(current_paragraph_content.split(' ')[0])))
                    current_paragraph_content = ""
                inside_paragraph = True
            if inside_paragraph:
                current_paragraph_content += line + "\n"

        if current_paragraph_content:
            paragraphs_and_levels.append((current_paragraph_content.strip(), len(current_paragraph_content.split(' ')[0])))

        return paragraphs_and_levels

    @staticmethod
    def _split_to_attack_cases(markdown: str, paragraphs_and_levels: list[tuple[str, int]]) -> list[tuple[str, list[tuple[str, int]]]]:
        attack_cases_paragraph_indexes = []
        i = 0
        while i < len(paragraphs_and_levels):
            paragraph, level = paragraphs_and_levels[i]
            if re.match(r'^#+ (attack )?(case|story) [1-9]: ', paragraph, re.IGNORECASE):
                attack_cases_paragraph_indexes.append([i])
                j = i + 1
                while j < len(paragraphs_and_levels) and paragraphs_and_levels[j][1] > level:
                    attack_cases_paragraph_indexes[-1].append(j)
                    j += 1
                i = j
            else:
                i += 1

        if not attack_cases_paragraph_indexes:
            return [(markdown, paragraphs_and_levels)]

        result = []
        for i in range(len(attack_cases_paragraph_indexes)):
            lower_attack_case_heading = ' '.join(paragraphs_and_levels[attack_cases_paragraph_indexes[i][0]][0].split('\n')[0].split(': ')[1:]).lower()
            if all(csp not in lower_attack_case_heading for csp in ['azure', 'gcp', 'google cloud']):
                current_markdown = markdown
                current_paragraphs_and_levels = paragraphs_and_levels.copy()
                for j in range(len(attack_cases_paragraph_indexes)-1, -1, -1):
                    if i != j:
                        for paragraph_index in reversed(attack_cases_paragraph_indexes[j]):
                            current_markdown = current_markdown.replace('\n\n' + current_paragraphs_and_levels[paragraph_index][0], '')
                            del current_paragraphs_and_levels[paragraph_index]
                result.append((current_markdown, current_paragraphs_and_levels))
            else:
                result.append(None)

        return result

    @staticmethod
    def _enhance_paragraphs(paragraphs_and_levels: list[tuple[str, int]]) -> list[str]:
        paragraphs = []
        for i, (paragraph, level) in enumerate(paragraphs_and_levels):
            current_level = level
            for prev_paragraph, prev_level in reversed(paragraphs_and_levels[:i]):
                if prev_level < current_level:
                    paragraph = prev_paragraph.split('\n')[0] + "\n\n" + paragraph
                    current_level = prev_level
            paragraphs.append(paragraph)

        return [paragraph for paragraph in paragraphs if not all(line.startswith('#') or not line for line in paragraph.split('\n'))]

    @staticmethod
    def _filter_paragraphs(paragraphs: list[str]) -> list[str]:
        unwanted_headings = {'overview', 'table of contents', 'tl;dr', 'summary', 'executive summary',
                             'attack summary', 'summary (tl;dr)', 'summary (the tl;dr)', 'conclusion',
                             'conclusions', 'lessons learned', 'attack summary and conclusion',
                             'attack summary and conclusions', 'summary and conclusion', 'summary and conclusions',
                             'recommendations', 'ioc', 'iocs', 'indicator of compromise',
                             'indicator of compromise (ioc)', 'indicators of compromise',
                             'indicators of compromise (ioc)', 'indicators of compromise (iocs)', 'indicators',
                             'atomic indicators', 'detections'}

        filtered_paragraphs = []
        for paragraph in paragraphs:
            headings = re.findall(r'^#+ .+$', paragraph, re.MULTILINE)
            if not any(heading.strip('# ').lower() in unwanted_headings for heading in headings):
                filtered_paragraphs.append(paragraph)

        return filtered_paragraphs

    def _analyze_images(self, markdown: str, paragraphs: list[str]) -> tuple[str, list[str]]:
        paragraph_index_to_image_urls = {}
        for i, paragraph in enumerate(paragraphs):
            image_urls = re.findall(r'\[Image Info:\n(?:- Alt Text: [^\n]+\n)?(?:- Caption: [^\n]+\n)?(https?://\S+)]', paragraph)
            if image_urls:
                paragraph_index_to_image_urls[i] = image_urls

        with ThreadPoolExecutor() as executor:
            future_to_paragraph_index_and_image_url = {executor.submit(self.image_analyzer.analyze_image, paragraphs[paragraph_index], len(image_urls), image_index, image_url): (paragraph_index, image_url) for paragraph_index, image_urls in paragraph_index_to_image_urls.items() for image_index, image_url in enumerate(image_urls)}
            for future in as_completed(future_to_paragraph_index_and_image_url):
                paragraph_index, image_url = future_to_paragraph_index_and_image_url[future]
                image_analysis = future.result()
                if image_analysis:
                    image_description, image_transcription = image_analysis
                    image_analysis = f'- Description: {image_description}\n- Transcription:\n{image_transcription}'
                    markdown = markdown.replace(image_url, image_analysis)
                    paragraphs[paragraph_index] = paragraphs[paragraph_index].replace(image_url, image_analysis)
                else:
                    markdown = re.sub(rf'\[Image Info:\n(?:- Alt Text: [^\n]+\n)?(?:- Caption: [^\n]+\n)?{re.escape(image_url)}]', '', markdown)
                    paragraphs[paragraph_index] = re.sub(rf'\[Image Info:\n(?:- Alt Text: [^\n]+\n)?(?:- Caption: [^\n]+\n)?{re.escape(image_url)}]', '', paragraphs[paragraph_index])

        return markdown, paragraphs

    def preprocess_oscti(self, url: str, include_images: bool = True) -> list[tuple[str, list[str]]] | None:
        result = []

        logging.info('\t\tDownloading HTML')
        html = Downloader.fetch_website(url)
        if html:
            logging.info(f'\t\tParsing HTML')
            markdown = Parser.parse_html(html, include_images)
            if markdown:
                logging.info(f'\t\tSplitting Markdown to paragraphs')
                paragraphs_and_levels = Preprocessor._split_to_paragraphs(markdown)
                logging.info(f'\t\tSplitting Markdown and paragraphs to attack cases')
                attack_cases = Preprocessor._split_to_attack_cases(markdown, paragraphs_and_levels)
                for attack_case in attack_cases:
                    if attack_case:
                        attack_case_markdown, attack_case_paragraphs_and_levels = attack_case
                        logging.info(f'\t\tEnhancing paragraphs with parent headings')
                        attack_case_paragraphs = Preprocessor._enhance_paragraphs(attack_case_paragraphs_and_levels)
                        if include_images:
                            logging.info(f'\t\tAnalyzing images')
                            attack_case_markdown, attack_case_paragraphs = self._analyze_images(attack_case_markdown, attack_case_paragraphs)
                        logging.info(f'\t\tFiltering paragraphs')
                        attack_case_paragraphs = Preprocessor._filter_paragraphs(attack_case_paragraphs)
                        result.append((attack_case_markdown, attack_case_paragraphs))
                    else:
                        logging.warning(f'\t\tAttack case is not related to AWS')
                        result.append(None)

                return result
        return None
