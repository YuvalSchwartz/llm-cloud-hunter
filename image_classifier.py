import os
from openai import OpenAI
import logging
from pydantic import BaseModel

from prompts.image_classification_prompts import image_classification_system_prompt, generate_image_classification_user_prompt


class ImageClassification(BaseModel):
    informative: bool
    description: str


class ImageClassifier:
    def __init__(self, model_name: str = 'gpt-4o-2024-08-06', api_key: str = None, temperature: float = 0.85):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature

    @staticmethod
    def _generate_image_classification_messages(paragraph: str, number_of_images: int, image_index: int, image_url: str):
        return [
            {"role": "system", "content": image_classification_system_prompt},
            {"role": "user", "content": [
                {"type": "text", "text": generate_image_classification_user_prompt(paragraph, number_of_images, image_index)},
                {"type": "image_url", "image_url": {"url": image_url}}]}
        ]

    def _send_image_classification_request(self, image_analysis_messages):
        return self.client.beta.chat.completions.parse(
            model=self.model_name,
            temperature=self.temperature,
            messages=image_analysis_messages,
            response_format=ImageClassification
        )

    def classify_image(self, paragraph: str, number_of_images: int, image_index: int, image_url: str) -> ImageClassification | None:
        messages = ImageClassifier._generate_image_classification_messages(paragraph, number_of_images, image_index, image_url)

        try:
            response = self._send_image_classification_request(messages)
        except Exception as e:
            logging.error(f"Error classifying image: {e}")
            return None

        return response.choices[0].message.parsed
