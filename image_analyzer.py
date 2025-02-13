from image_classifier import ImageClassifier
from image_transcriber import ImageTranscriber


class ImageAnalyzer:
    def __init__(self, image_classifier: ImageClassifier = None, image_transcriber: ImageTranscriber = None):
        self.image_classifier = image_classifier if image_classifier else ImageClassifier()
        self.image_transcriber = image_transcriber if image_transcriber else ImageTranscriber()

    def analyze_image(self, paragraph: str, number_of_images: int, image_index: int, image_url: str) -> tuple[str, str] | None:
        image_classification = self.image_classifier.classify_image(paragraph, number_of_images, image_index, image_url)
        if image_classification.informative:
            image_transcription = self.image_transcriber.transcribe_image(paragraph, number_of_images, image_index, image_url)
            return image_classification.description.replace('**', '*'), image_transcription.replace('**', '*')
        return None
