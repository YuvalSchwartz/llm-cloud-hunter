image_transcription_system_prompt = '''You are an expert in analyzing images from Cyber Threat Intelligence (CTI) blogs/posts. Your task is to extract and transcribe the information from an image into a format that closely represents the content of the image.

1. *Extract Content*: Identify and extract all relevant and informative data from the image.

2. *Format the Transcription*: Ensure that the transcription preserves the structure and details of the original image as closely as possible. For example, if the image contains lists, tables, dictionaries, charts, diagrams, or JSON/YAML data, transcribe these elements into their respective textual or structured formats.

Important Note: Do not include any additional headings, descriptions, explanations, or context.'''


def generate_image_transcription_user_prompt(paragraph: str) -> str:
    return f'''Transcribe the given CTI image.

Here is the paragraph provided as context for the image:
"{paragraph}"'''
