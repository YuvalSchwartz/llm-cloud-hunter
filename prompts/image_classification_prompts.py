image_classification_system_prompt = '''You are an expert in analyzing images from Cyber Threat Intelligence (CTI) blogs/posts. Your task is to classify each image as either informative or non-informative and provide a concise but detailed description of the image. 

1. *Classify the Image*:
   - Informative: This includes images like screenshots, charts, diagrams, lists, tables, or any content that provides valuable, specific information relevant to the CTI content (e.g., technical data, attack details).
   - Non-Informative: This includes images that serve an aesthetic purpose, advertising, visual metaphors/abstractions, or do not add detailed, technical value to the CTI content (e.g., decorative art, photos of people, generic symbols).

2. *Description*: Provide a textual description of the image, summarizing what is depicted in the image.'''


def generate_image_classification_user_prompt(paragraph: str, number_of_images: int, image_index: int) -> str:
    if number_of_images == 1:
        parentheses_text = 'there is only one image in the paragraph'
    else:
        parentheses_text = f'there are {number_of_images} images in the paragraph, and this is image number {image_index + 1}'

    return f'''Analyze the given CTI image.

Paragraph provided as context for the image ({parentheses_text}): """
{paragraph}
"""'''
