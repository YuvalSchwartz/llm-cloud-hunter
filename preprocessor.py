import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from downloader import Downloader
from parser import Parser
from image_analyzer import ImageAnalyzer


class Preprocessor:
    def __init__(self, image_analyzer: ImageAnalyzer = None):
        self.image_analyzer = image_analyzer if image_analyzer else ImageAnalyzer()

    @staticmethod
    def _split_to_paragraphs(markdown: str) -> List[Tuple[str, int]]:
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
    def _filter_attack_cases(markdown: str, paragraphs_and_levels: List[Tuple[str, int]]) -> Tuple[str, List[Tuple[str, int]]]:
        paragraph_indexes_to_remove = []
        i = 0
        while i < len(paragraphs_and_levels):
            paragraph, level = paragraphs_and_levels[i]
            if re.match(r'^#+\s(attack\s)?(case|story)\s[2-9]:\s', paragraph, re.IGNORECASE):
                paragraph_indexes_to_remove.append(i)
                j = i + 1
                while j < len(paragraphs_and_levels) and paragraphs_and_levels[j][1] > level:
                    paragraph_indexes_to_remove.append(j)
                    j += 1
                i = j
            else:
                i += 1

        for paragraph_index in reversed(paragraph_indexes_to_remove):
            markdown = markdown.replace('\n\n' + paragraphs_and_levels[paragraph_index][0], '')
            del paragraphs_and_levels[paragraph_index]

        return markdown, paragraphs_and_levels

    @staticmethod
    def _enhance_paragraphs(paragraphs_and_levels: List[Tuple[str, int]]) -> List[str]:
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
    def _filter_paragraphs(paragraphs: List[str]) -> List[str]:
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

    def _analyze_images(self, markdown: str, paragraphs: List[str]) -> Tuple[str, List[str]]:
        paragraph_index_to_image_urls = {}
        for i, paragraph in enumerate(paragraphs):
            image_urls = re.findall(r'\[Image Info:\n(?:- Alt Text: [^\n]+\n)?(?:- Caption: [^\n]+\n)?(https?://\S+)]', paragraph)
            if image_urls:
                paragraph_index_to_image_urls[i] = image_urls

        with ThreadPoolExecutor() as executor:
            future_to_paragraph_index_and_image_url = {executor.submit(self.image_analyzer.analyze_image, paragraphs[paragraph_index], image_url): (paragraph_index, image_url) for paragraph_index, image_urls in paragraph_index_to_image_urls.items() for image_url in image_urls}
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

    def preprocess_oscti(self, url: str, include_images: bool = True, return_image_count: bool = False) -> Tuple[str, List[str], int] | Tuple[str, List[str]] | None:
        logging.info('\t\tDownloading HTML')
        html = Downloader.fetch_website(url)
        if html:
            logging.info(f'\t\tParsing HTML')
            markdown, image_count = Parser.parse_html(html, include_images)
            if markdown:
                logging.info(f'\t\tSplitting Markdown to paragraphs')
                paragraphs_and_levels = Preprocessor._split_to_paragraphs(markdown)
                logging.info(f'\t\tFiltering attack cases')
                markdown, paragraphs_and_levels = Preprocessor._filter_attack_cases(markdown, paragraphs_and_levels)
                logging.info(f'\t\tEnhancing paragraphs with parent headings')
                paragraphs = Preprocessor._enhance_paragraphs(paragraphs_and_levels)
                if include_images:
                    logging.info(f'\t\tAnalyzing images')
                    markdown, paragraphs = self._analyze_images(markdown, paragraphs)
                logging.info(f'\t\tFiltering paragraphs')
                paragraphs = Preprocessor._filter_paragraphs(paragraphs)
                if return_image_count:
                    return markdown, paragraphs, image_count
                return markdown, paragraphs
        return None


if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv()
    url = 'https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts'
    markdown, _ = Preprocessor().preprocess_oscti(url, include_images=True, return_image_count=False)
    print(markdown)
