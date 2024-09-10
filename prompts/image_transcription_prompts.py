image_transcription_system_prompt = '''You are an expert in analyzing images from Cyber Threat Intelligence (CTI) blogs/posts. Your task is to extract and transcribe the information from an image into a format that closely represents the content of the image.

1. *Extract Content*: Identify and extract all relevant and informative data from the image.
2. *Format the Transcription*: Ensure that the transcription preserves the structure and details of the original image as closely as possible. For example, if the image contains lists, tables, dictionaries, charts, diagrams, or JSON/YAML data, transcribe these elements into their respective textual or structured formats.

Important Note: Do not include any additional headings, descriptions, explanations, or context.'''


def generate_image_transcription_user_prompt(paragraph: str, number_of_images: int, image_index: int) -> str:
    if number_of_images == 1:
        parentheses_text = 'there is only one image in the paragraph'
    else:
        parentheses_text = f'there are {number_of_images} images in the paragraph, and this is image number {image_index + 1}'

    return f'''Transcribe the given CTI image.

For context, here is the paragraph from which the image was extracted ({parentheses_text}): """
{paragraph}
"""'''
