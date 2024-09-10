import os
from openai import OpenAI
import logging

from prompts.image_transcription_prompts import image_transcription_system_prompt, generate_image_transcription_user_prompt


class ImageTranscriber:
    def __init__(self, model_name: str = "chatgpt-4o-latest", api_key: str = None, temperature: float = 0.3):
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key if api_key else os.getenv('OPENAI_API_KEY'))
        self.temperature = temperature

    @staticmethod
    def _generate_image_transcription_messages(paragraph: str, number_of_images: int, image_index: int, image_url: str):
        return [
            {"role": "system", "content": image_transcription_system_prompt},
            {"role": "user", "content": [
                {"type": "text", "text": generate_image_transcription_user_prompt(paragraph, number_of_images, image_index)},
                {"type": "image_url", "image_url": {"url": image_url}}]}
        ]

    def _send_image_transcription_request(self, image_analysis_messages):
        return self.client.chat.completions.create(
            model=self.model_name,
            messages=image_analysis_messages,
            temperature=self.temperature
        )

    def transcribe_image(self, paragraph: str, number_of_images: int, image_index: int, image_url: str) -> str | None:
        messages = ImageTranscriber._generate_image_transcription_messages(paragraph, number_of_images, image_index, image_url)

        try:
            response = self._send_image_transcription_request(messages)
        except Exception as e:
            logging.error(f"Error transcribing image: {e}")
            return None

        return response.choices[0].message.content.strip(' \n`')
