import os
from openai import OpenAI
import logging
from pydantic import BaseModel

from prompts.image_classification_prompts import image_classification_system_prompt, generate_image_classification_user_prompt


class ImageClassification(BaseModel):
    informative: bool
    description: str


class ImageClassifier:
    def __init__(self, model="gpt-4o-2024-08-06", api_key=None):
        self.model = model
        self._api_key = api_key if api_key else os.getenv('OPENAI_API_KEY')
        self.client = OpenAI(api_key=self._api_key)

    @staticmethod
    def _generate_image_classification_messages(paragraph: str, image_url: str):
        return [
            {"role": "system", "content": image_classification_system_prompt},
            {"role": "user", "content": [
                {"type": "text", "text": generate_image_classification_user_prompt(paragraph)},
                {"type": "image_url", "image_url": {"url": image_url}}]}
        ]

    def _send_image_classification_request(self, image_analysis_messages):
        return self.client.beta.chat.completions.parse(
            model=self.model,
            messages=image_analysis_messages,
            response_format=ImageClassification
        )

    def classify_image(self, paragraph: str, image_url):
        messages = ImageClassifier._generate_image_classification_messages(paragraph, image_url)

        try:
            response = self._send_image_classification_request(messages)
        except Exception as e:
            logging.error(f"Error classifying image: {e}")
            return None

        return response.choices[0].message.parsed
