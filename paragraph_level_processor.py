from concurrent.futures import ThreadPoolExecutor, as_completed

from explicit_api_call_extractor import ExplicitApiCallExtractor
from implicit_api_call_extractor import ImplicitApiCallExtractor
from ttp_classifier import TTPClassifier
from criticality_classifier import CriticalityClassifier
from rule_generator import RuleGenerator


class ParagraphLevelProcessor:
    def __init__(self, explicit_api_call_extractor: ExplicitApiCallExtractor = None, implicit_api_call_extractor: ImplicitApiCallExtractor = None, ttp_extractor: TTPClassifier = None, criticality_extractor: CriticalityClassifier = None, rule_generator: RuleGenerator = None):
        self.explicit_api_call_extractor = explicit_api_call_extractor if explicit_api_call_extractor else ExplicitApiCallExtractor()
        self.implicit_api_call_extractor = implicit_api_call_extractor if implicit_api_call_extractor else ImplicitApiCallExtractor()
        self.ttp_extractor = ttp_extractor if ttp_extractor else TTPClassifier()
        self.criticality_extractor = criticality_extractor if criticality_extractor else CriticalityClassifier()
        self.rule_generator = rule_generator if rule_generator else RuleGenerator()

    # def _process_paragraph(self, paragraph: str) -> dict | list[dict] | None:
    #     explicit_event_to_source = self.explicit_api_call_extractor.extract_explicit_api_calls(paragraph)
    #     if explicit_event_to_source:
    #         implicit_event_to_source = self.implicit_api_call_extractor.extract_implicit_api_calls(paragraph, explicit_event_to_source)
    #         final_event_to_source = {**explicit_event_to_source, **implicit_event_to_source}
    #         event_to_ttps = self.ttp_extractor.classify_api_call_ttp(final_event_to_source, paragraph)
    #         events = [{'eventName': event, 'eventSource': source, 'tags': event_to_ttps[event]} for event, source in final_event_to_source.items()]
    #         event_to_criticality = self.criticality_extractor.classify_api_call_criticality(events, paragraph)
    #         for event in events:
    #             event['level'] = event_to_criticality[event['eventName']]
    #         rules = self.rule_generator.generate_rules(paragraph, events)
    #
    #         return rules
    #
    #     return None
    def _process_paragraph(self, paragraph: str) -> dict | list[dict] | None:
        explicit_event_to_source = self.explicit_api_call_extractor.extract_explicit_api_calls(paragraph)
        if not explicit_event_to_source:
            return None

        implicit_event_to_source = self.implicit_api_call_extractor.extract_implicit_api_calls(paragraph,
                                                                                               explicit_event_to_source)
        final_event_to_source = {**explicit_event_to_source, **implicit_event_to_source}
        event_to_ttps = self.ttp_extractor.classify_api_call_ttp(final_event_to_source, paragraph)

        try:
            # Normalize keys in final_event_to_source and event_to_ttps
            final_event_to_source = {self._normalize_key(key): value for key, value in final_event_to_source.items()}
            event_to_ttps = {self._normalize_key(key): value for key, value in event_to_ttps.items()}

            events = []
            for event, source in final_event_to_source.items():
                ttp = event_to_ttps.get(event)
                if ttp:
                    events.append({'eventName': event, 'eventSource': source, 'tags': ttp})
                else:
                    print(f"Warning: No TTP found for event {event}")

            if not events:
                print("No valid events found, skipping.")
                return None

            event_to_criticality = self.criticality_extractor.classify_api_call_criticality(events, paragraph)
            for event in events:
                event['level'] = event_to_criticality.get(event['eventName'], 'Unknown')

            rules = self.rule_generator.generate_rules(paragraph, events)
            return rules

        except Exception as e:
            print(f"Error in _process_paragraph: {str(e)}")
            print("Debug information:")
            print(f"final_event_to_source: {final_event_to_source}")
            print(f"event_to_ttps: {event_to_ttps}")
            print(f"paragraph: {paragraph}")
            return None

    def _normalize_key(self, key: str) -> str:
        """Normalize keys by removing common prefixes and suffixes."""
        prefixes_to_remove = ['iam:', 'ec2:', 's3:']  # Add more prefixes as needed
        for prefix in prefixes_to_remove:
            if key.startswith(prefix):
                key = key[len(prefix):]
        return key.split(':')[-1].split('.')[-1]

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
