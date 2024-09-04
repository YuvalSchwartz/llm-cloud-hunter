from concurrent.futures import ThreadPoolExecutor, as_completed

from explicit_api_call_extractor import ExplicitApiCallExtractor
from implicit_api_call_extractor import ImplicitApiCallExtractor
from ttp_classifier import TTPClassifier
from criticality_classifier import CriticalityClassifier
from rule_generator import RuleGenerator
from utils import sanitize_rule


class ParagraphLevelProcessor:
    def __init__(self, explicit_api_call_extractor: ExplicitApiCallExtractor = None, implicit_api_call_extractor: ImplicitApiCallExtractor = None, ttp_extractor: TTPClassifier = None, criticality_extractor: CriticalityClassifier = None, rule_generator: RuleGenerator = None):
        self.explicit_api_call_extractor = explicit_api_call_extractor if explicit_api_call_extractor else ExplicitApiCallExtractor()
        self.implicit_api_call_extractor = implicit_api_call_extractor if implicit_api_call_extractor else ImplicitApiCallExtractor()
        self.ttp_extractor = ttp_extractor if ttp_extractor else TTPClassifier()
        self.criticality_extractor = criticality_extractor if criticality_extractor else CriticalityClassifier()
        self.rule_generator = rule_generator if rule_generator else RuleGenerator()

    def _process_paragraph(self, paragraph: str) -> dict | list[dict] | None:
        explicit_event_to_source = self.explicit_api_call_extractor.extract_explicit_api_calls(paragraph)
        if explicit_event_to_source:
            implicit_event_to_source = self.implicit_api_call_extractor.extract_implicit_api_calls(paragraph, explicit_event_to_source)
            final_event_to_source = {**explicit_event_to_source, **implicit_event_to_source}
            event_to_ttps = self.ttp_extractor.classify_api_call_ttp(final_event_to_source, paragraph)
            # TODO: change the following
            # events = [{'eventName': event, 'eventSource': source, 'tags': event_to_ttps[event]} for event, source in final_event_to_source.items()]
            events = [{'method_name': event, 'service_name': source, 'tags': event_to_ttps[event]} for event, source in final_event_to_source.items()]
            # TODO: change the above
            event_to_criticality = self.criticality_extractor.classify_api_call_criticality(events, paragraph)
            # TODO: change the following
            # events = [{'eventName': event, 'eventSource': source, 'tags': event_to_ttps[event], 'level': event_to_criticality[event]} for event, source in final_event_to_source.items()]
            events = [{'method_name': event, 'service_name': source, 'tags': event_to_ttps[event], 'level': event_to_criticality[event]} for event, source in final_event_to_source.items()]
            # TODO: change the above
            rules = self.rule_generator.generate_rules(paragraph, events)
            if rules:
                if isinstance(rules, dict):
                    rules = [rules]
                rules = [sanitize_rule(rule) for rule in rules]
                if len(rules) == 1:
                    rules = rules[0]

                return rules

        return None

    def process_paragraphs(self, paragraphs: list[str]) -> dict | list[dict] | None:
        results = [None] * len(paragraphs)
        with ThreadPoolExecutor() as executor:
            future_to_index = {executor.submit(self._process_paragraph, paragraph): index for index, paragraph in enumerate(paragraphs)}
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                rules = future.result()
                results[index] = rules

        final_results = []
        for result in results:
            if result:
                if isinstance(result, dict):
                    final_results.append(result)
                elif isinstance(result, list):
                    final_results.extend(result)
        if final_results:
            return final_results

        return None
