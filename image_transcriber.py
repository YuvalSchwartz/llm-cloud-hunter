import os
from openai import OpenAI
import logging

from prompts.image_transcription_prompts import image_transcription_system_prompt, generate_image_transcription_user_prompt


class ImageTranscriber:
    def __init__(self, model="chatgpt-4o-latest", api_key=None):
        self.model = model
        self._api_key = api_key if api_key else os.getenv('OPENAI_API_KEY')
        self.client = OpenAI(api_key=self._api_key)

    @staticmethod
    def _generate_image_transcription_messages(paragraph: str, image_url: str):
        return [
            {"role": "system", "content": image_transcription_system_prompt},
            {"role": "user", "content": [
                {"type": "text", "text": generate_image_transcription_user_prompt(paragraph)},
                {"type": "image_url", "image_url": {"url": image_url}}]}
        ]

    def _send_image_transcription_request(self, image_analysis_messages):
        return self.client.chat.completions.create(
            model=self.model,
            messages=image_analysis_messages,
            temperature=0.75
        )

    def transcribe_image(self, paragraph: str, image_url):
        messages = ImageTranscriber._generate_image_transcription_messages(paragraph, image_url)

        try:
            response = self._send_image_transcription_request(messages)
        except Exception as e:
            logging.error(f"Error transcribing image: {e}")
            return None

        return response.choices[0].message.content.strip(' \n`')
