from bs4 import Tag, BeautifulSoup, NavigableString, Comment
import re
import json
import yaml
import logging

from utils import dump_yaml


class Parser:
    @staticmethod
    def _clean_soup(soup: BeautifulSoup) -> None:
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()

        for invisible_element in soup.find_all(style=re.compile(r'display\s*:\s*none', re.IGNORECASE)):
            invisible_element.decompose()

        tags_to_remove = ['nav', 'meta', 'style', 'script', 'noscript', 'form', 'button', 'aside', 'source']
        for tag in tags_to_remove:
            for element in soup.find_all(tag):
                element.decompose()

    @staticmethod
    def _fix_structure(element: Tag) -> None:
        if not element.decomposed:
            children = list(element.children)
            i = 0
            while i < len(children):
                child = children[i]
                if isinstance(child, Tag) and not child.decomposed:
                    if child.name == 'p' or child.name == 'em':
                        p_children = list(child.children)
                        img_index = next((index for index, p_child in enumerate(p_children) if isinstance(p_child, Tag) and p_child.name == 'img'), None)
                        if img_index is not None:
                            before_img = p_children[:img_index]
                            img_tag = p_children[img_index]
                            after_img = p_children[img_index + 1:]
                            if before_img:
                                new_p_before = Tag(name='p')
                                new_p_before.extend(before_img)
                                child.clear()
                                child.extend(before_img)
                                child.insert_after(img_tag)
                            else:
                                child.replace_with(img_tag)
                                child = img_tag
                            if after_img:
                                new_p_after = Tag(name='p')
                                new_p_after.extend(after_img)
                                img_tag.insert_after(new_p_after)
                            children = list(element.children)
                            if child.name == 'img':
                                continue
                        tag_children = [tag for tag in list(child.children) if isinstance(tag, Tag) if tag.name != 'br']
                        if len(tag_children) == 0 and child.string and child.string.lower() in {'ioc', 'iocs', 'reference', 'references'}:
                            child.name = 'h2'
                        elif len(tag_children) == 1:
                            if tag_children[0].name in {'i', 'noscript'}:
                                child.replace_with(tag_children[0])
                                child = tag_children[0]
                            elif tag_children[0].name == 'span' and child.text.strip() == tag_children[0].text.strip():
                                tag_grandchildren = [tag for tag in list(tag_children[0].children) if isinstance(tag, Tag)]
                                if len(tag_grandchildren) == 1 and tag_grandchildren[0].name == 'em':
                                    em_grandchildren = [tag for tag in list(tag_grandchildren[0].children) if isinstance(tag, Tag)]
                                    if len(em_grandchildren) == 1 and em_grandchildren[0].name == 'img':
                                        img = em_grandchildren[0]
                                        img.extract()
                                        tag_children[0].insert_before(img)
                                        continue
                                    elif not em_grandchildren:
                                        child.replace_with(tag_grandchildren[0])
                                        child = tag_grandchildren[0]
                                        child.name = 'figcaption'
                                child.name = 'p'
                            elif tag_children[0].name == 'a':
                                tag_grandchildren = [tag for tag in list(tag_children[0].children) if isinstance(tag, Tag)]
                                if len(tag_grandchildren) == 1 and tag_grandchildren[0].name == 'img':
                                    child.replace_with(tag_grandchildren[0])
                                    child = tag_grandchildren[0]
                    if child.name == 'li':
                        tag_children = [tag for tag in list(child.children) if isinstance(tag, Tag)]
                        if len(tag_children) > 1 and all(tag.name == 'p' for tag in tag_children) and all(len([t for t in list(tag.children) if isinstance(t, Tag)]) == 0 or (len([t for t in list(tag.children) if isinstance(t, Tag)]) == 1 and [t for t in list(tag.children) if isinstance(t, Tag)][0].name == 'code') for tag in tag_children):
                            new_p_tag = Tag(name='p')
                            add_space = False
                            for tag in tag_children:
                                for tag_child in list(tag.children):
                                    if isinstance(tag_child, Tag):
                                        if len(list(new_p_tag.children)) > 0 and isinstance(list(new_p_tag.children)[-1], NavigableString):
                                            list(new_p_tag.children)[-1].replace_with(str(list(new_p_tag.children)[-1]) + ' ')
                                        add_space = True
                                    else:
                                        if add_space:
                                            tag_child = NavigableString(' ' + str(tag_child))
                                            add_space = False
                                    new_p_tag.append(tag_child)
                                tag.decompose()
                            child.append(new_p_tag)
                    elif child.name == 'img':
                        next_sibling = child.find_next_sibling()
                        if next_sibling and (next_sibling.name == 'p' or next_sibling.name == 'span'):
                            next_sibling_tag_children = [tag for tag in list(next_sibling.children) if isinstance(tag, Tag)]
                            if len(next_sibling_tag_children) == 1:
                                if next_sibling_tag_children[0].name == 'em':
                                    em_tag = next_sibling_tag_children[0]
                                    em_tag.name = 'figcaption'
                                    next_sibling.replace_with(em_tag)
                                elif next_sibling_tag_children[0].name == 'p' or next_sibling_tag_children[0].name == 'span':
                                    next_sibling_child_tag_children = [tag for tag in list(next_sibling_tag_children[0].children) if isinstance(tag, Tag)]
                                    if len(next_sibling_child_tag_children) == 1 and next_sibling_child_tag_children[0].name == 'em':
                                        em_tag = next_sibling_child_tag_children[0]
                                        em_tag.name = 'figcaption'
                                        next_sibling.replace_with(em_tag)
                    elif child.name == 'table':
                        tag_children = [tag for tag in list(child.children) if isinstance(tag, Tag)]
                        if len(tag_children) == 1 and tag_children[0].name == 'thead':
                            next_sibling = child.find_next_sibling()
                            if next_sibling and next_sibling.name == 'table':
                                next_sibling_tag_children = [tag for tag in list(next_sibling.children) if isinstance(tag, Tag)]
                                if len(next_sibling_tag_children) == 1 and next_sibling_tag_children[0].name == 'tbody':
                                    next_sibling.insert(0, tag_children[0])
                                    child.decompose()
                                    children = list(element.children)
                        else:
                            thead_tag = child.find('thead')
                            if thead_tag and not thead_tag.text.strip():
                                thead_tag.decompose()
                    elif child.name == 'div':
                        tag_children = [tag for tag in list(child.children) if isinstance(tag, Tag)]
                        if tag_children and all(tag.name == 'pre' for tag in tag_children):
                            if all(all(tag.name == 'code' for tag in list(pre.children) if isinstance(tag, Tag)) for pre in tag_children):
                                new_pre_tag = Tag(name='pre')
                                new_code_tag = Tag(name='code')
                                new_pre_tag.append(new_code_tag)
                                for tag in tag_children:
                                    for code_tag in list(tag.children):
                                        for code_tag_child in list(code_tag.children):
                                            new_code_tag.append(code_tag_child)
                                    tag.decompose()
                                child.append(new_pre_tag)
                        elif len(tag_children) == 2 and tag_children[0].name == 'picture' and tag_children[1].name == 'div' and not tag_children[1].text.strip():
                            tag_children[1].decompose()
                    elif child.name == 'span':
                        span_tag_children = [tag for tag in list(child.children) if isinstance(tag, Tag)]
                        if len(span_tag_children) == 1 and span_tag_children[0].name == 'span':
                            span_tag_children = [tag for tag in list(span_tag_children[0].children) if isinstance(tag, Tag)]
                            if len(span_tag_children) == 1 and span_tag_children[0].name == 'p':
                                p_tag_children = [tag for tag in list(span_tag_children[0].children) if isinstance(tag, Tag)]
                                if len(p_tag_children) == 1 and p_tag_children[0].name == 'span':
                                    span_tag_children = [tag for tag in list(p_tag_children[0].children) if isinstance(tag, Tag)]
                                    if len(span_tag_children) == 1 and span_tag_children[0].name == 'i':
                                        child.replace_with(span_tag_children[0])
                    elif child.name == 'strong':
                        tag_children = [tag for tag in list(child.children) if isinstance(tag, Tag)]
                        if len(tag_children) == 1 and tag_children[0].name == 'code' and child.text.strip() == tag_children[0].text.strip():
                            child.replace_with(tag_children[0])

                    Parser._fix_structure(child)

                i += 1

    @staticmethod
    def _is_descendant(parent: Tag, child: Tag | NavigableString) -> bool:
        ancestor = child.parent
        while ancestor is not None:
            if ancestor == parent:
                return True
            ancestor = ancestor.parent
        return False

    @staticmethod
    def _get_previous_outer_element(element: Tag, tag_names_to_skip: set[str] = None) -> Tag | NavigableString | None:
        previous_tag = None
        previous_navigable_string = None
        previous_element = element.previous

        while True:
            if previous_element is None or (previous_tag and previous_navigable_string):
                break
            if not Parser._is_descendant(previous_element, element):
                if not previous_navigable_string and isinstance(previous_element, NavigableString) and not isinstance(previous_element, Comment) and previous_element != '\n' and previous_element != ' ':
                    previous_navigable_string = previous_element
                if not previous_tag and isinstance(previous_element, Tag) and (not tag_names_to_skip or (tag_names_to_skip and previous_element.name not in tag_names_to_skip)):
                    previous_tag = previous_element
            previous_element = previous_element.previous

        if not previous_navigable_string and not previous_tag:
            return None
        if previous_navigable_string and not previous_tag:
            return previous_navigable_string
        elif previous_tag and not previous_navigable_string:
            return previous_tag
        else:
            if Parser._is_descendant(previous_tag, previous_navigable_string) and not Parser._is_descendant(previous_tag, element):
                return previous_tag
            else:
                return previous_navigable_string

    @staticmethod
    def _get_next_outer_element(element: Tag, tag_names_to_skip: set[str] = None, ) -> Tag | NavigableString | None:
        next_element = element.next

        while True:
            if next_element is None:
                return None
            if not Parser._is_descendant(element, next_element):
                if isinstance(next_element, NavigableString) and not isinstance(next_element, Comment) and next_element != '\n' and next_element != ' ':
                    return next_element
                if isinstance(next_element, Tag) and (not tag_names_to_skip or (tag_names_to_skip and next_element.name not in tag_names_to_skip)):
                    return next_element
            next_element = next_element.next

    @staticmethod
    def _filter_elements(element: Tag, include_images: bool = True, content_finished: bool = False) -> bool:
        if not element.decomposed:
            for child in list(element.children):
                if isinstance(child, Tag) and not child.decomposed:
                    if content_finished:
                        child.decompose()
                    elif child.name == 'footer':
                        if not child.find_next('footer'):
                            content_finished = True
                            child.decompose()
                        elif child.get('class', []) == ['blog-post-meta']:
                            child.decompose()
                    elif child.name in {'img', 'figure'}:
                        if not include_images:
                            next_element = Parser._get_next_outer_element(child)
                            if isinstance(next_element, Tag) and next_element.name in {'em', 'figcaption'}:
                                next_element.decompose()
                            child.decompose()
                        elif 'alignright' in child.get('class', []) or element.name == 'li':
                            child.decompose()
                    elif child.name == 'figcaption' and child.text.lower().strip() == '(click to enlarge)':
                        child.decompose()
                    elif child.name in {'i', 'em'} and child.text.lower().strip().startswith('updated'):
                        child.decompose()
                    elif child.name == 'br':
                        next_element = Parser._get_next_outer_element(child)
                        if isinstance(next_element, Tag) and next_element.name == 'br':
                            child.decompose()
                    elif child.name == 'li':
                        stripped_lower_text = child.text.lower().strip()
                        if (stripped_lower_text.startswith('by:') or stripped_lower_text.startswith('published:')) and len(stripped_lower_text) < 100:
                            child.decompose()
                    elif child.name in {'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'a', 'small', 'template', 'div', 'span'}:
                        classes = child.get('class', [])
                        combined_classes = ' '.join(classes).replace('_', '-')
                        while '--' in combined_classes:
                            combined_classes = combined_classes.replace('--', '-')
                        stripped_lower_text = child.text.lower().strip()
                        if child.name in {'h1', 'h2', 'h3', 'h4', 'h5', 'h6'}:
                            if stripped_lower_text.startswith('learn more about') and not child.find_next(lambda tag: tag.name in {'h1', 'h2', 'h3', 'h4', 'h5', 'h6'}):
                                content_finished = True
                                child.decompose()
                            elif stripped_lower_text == '' or stripped_lower_text == 'expel blog' or 'date-header' in combined_classes:
                                child.decompose()
                        elif child.name == 'p':
                            if (len([tag for tag in list(child.children) if isinstance(tag, Tag)]) == 0 and not child.string) or child.string == '\xa0' or child.string == '\u200d' or stripped_lower_text.startswith('this post is also available in') or stripped_lower_text == 'research' or 'date' in combined_classes:
                                child.decompose()
                        elif child.name == 'a':
                            unwanted_classes = ['card-category', 'twitter-follow-button']
                            if (child.get('href', '') == '/' and stripped_lower_text == '..') or stripped_lower_text in {'register now!', 'permalink', 'comments', 'share'} or any(unwanted_class in combined_classes for unwanted_class in unwanted_classes):
                                child.decompose()
                        elif child.name == 'small' and 'language' in combined_classes:  # If there are false negatives, consider using the aria-describedby attribute of the <pre> tag
                            child.decompose()
                        elif child.name == 'template':
                            unwanted_classes = ['js-file-alert-template', 'js-line-alert-template']
                            if any(unwanted_class in combined_classes for unwanted_class in unwanted_classes):
                                child.decompose()
                        elif child.name in {'div', 'span'}:
                            unwanted_classes = ['page-top', 'nav', 'breadcrumb', 'breadcrumbs', 'custom-meta', 'reading-time', 'function-list', 'duration', 'sidebar', 'table-of-contents', 'menu', 'dropdown', 'github-buttons', 'post-date', 'time-blog', 'author', 'back-to-blog', 'post-footer', 'button', 'btn', 'google-auto-placed', 'adsbygoogle', 'gist-meta', 'modal', 'subscribe', 'form', 'subscribeFormModal', 'close', 'latest-blogs', 'related-threat', 'newsletter', 'be-tags-wrapper', 'social', 'share-article', 'feedback-card']
                            unwanted_ids = ['sidebar', 'meta']
                            if stripped_lower_text.count('cookie') >= 5 or ((stripped_lower_text.startswith('by:') or stripped_lower_text.startswith('published:') or stripped_lower_text.startswith('credits:') or stripped_lower_text.startswith('acknowledgements:') or stripped_lower_text.startswith('related products') or stripped_lower_text.startswith('share') or stripped_lower_text == 'plain text') and len(stripped_lower_text) < 120) or any(unwanted_class in combined_classes for unwanted_class in unwanted_classes) or combined_classes == 'date' or any(unwanted_id in child.get('id', '').lower() for unwanted_id in unwanted_ids):
                                if 'post-footer' in combined_classes:
                                    content_finished = True
                                child.decompose()

                    content_finished = Parser._filter_elements(child, include_images, content_finished)

        return content_finished

    @staticmethod
    def _is_descendant_of_name(child: Tag, names) -> bool:
        if isinstance(names, str):
            names = {names}
        elif isinstance(names, list):
            names = set(names)

        # Check if the child is a descendant of an unordered or ordered list
        ancestor = child.parent
        while ancestor is not None:
            if ancestor.name in names:
                return True
            ancestor = ancestor.parent
        return False

    @staticmethod
    def _is_likely_command(text: str) -> bool:
        strings = text.split()
        strings_with_slashes = [string for string in strings if "\\" in string or '/' in string]
        return len(strings_with_slashes) / len(strings) > 0.5 if strings else False

    @staticmethod
    def _refine_text(text: str) -> str:
        inside_code = False
        inside_table = False
        lines = text.strip().split('\n')
        for i in range(len(lines)):
            stripped_line = lines[i].strip()
            if stripped_line == '```':
                inside_code = not inside_code
            elif not inside_table and stripped_line.startswith('+') and all(c in {'+', '-'} for c in stripped_line):
                inside_table = True
            elif inside_table and stripped_line.startswith('+') and all(c in {'+', '-'} for c in stripped_line) and i < len(lines) - 1 and lines[i + 1].strip() == '':
                inside_table = False
            elif not inside_code and not inside_table and stripped_line != '' and not stripped_line.startswith('_'):
                # Fix extra spaces
                lines[i] = re.sub(r'(\S) {2,}(\S)', r'\1 \2', lines[i])
                # Fix lack of spacing after punctuation
                lines[i] = re.sub(r'( [a-z]{2,})([.,])([A-Z][a-z]+)', r'\1\2 \3', lines[i])
                # Fix spacing before punctuation
                lines[i] = re.sub(r'([a-zA-Z0-9)\]}>\'`‘’‛“”‟"]) +([.,:;?!])', r'\1\2', lines[i])
                # Fix spacing after an opening bracket
                lines[i] = re.sub(r"([(\[{<«]) +([a-zA-Z0-9'`‘’‛“”‟\"])", r'\1\2', lines[i])
                # Fix spacing before a closing bracket
                lines[i] = re.sub(r"([a-zA-Z0-9'`‘’‛“”‟\"]) +([)\]}>»])", r'\1\2', lines[i])
                # Switching the order of a period/comma and a quotation mark if needed
                lines[i] = re.sub(r"([.,])(['‘’‛“”‟\"])( [a-zA-Z])?", r'\2\1\3', lines[i])

                # Check if the line is likely a URL path or a code command
                if not Parser._is_likely_command(lines[i]):
                    # Fix unbalanced spacing around slashes
                    lines[i] = re.sub(r'(\S)\s/(\S)', r'\1 / \2', lines[i])
                    lines[i] = re.sub(r'(\S)/\s(\S)', r'\1 / \2', lines[i])

                # Remove unwanted characters around backticks
                lines[i] = re.sub(r"(['‘’‛“”‟\"])`(.+)`(['‘’‛“”‟\"])", r'`\2`', lines[i])

                line_lower = lines[i].lower()
                if line_lower.endswith('. source'):
                    lines[i] = lines[i][:-7]
                elif line_lower.endswith('. source.'):
                    lines[i] = lines[i][:-8]
                elif line_lower.endswith('. (source)'):
                    lines[i] = lines[i][:-9]
                elif line_lower.endswith(' (source).'):
                    lines[i] = lines[i][:-10] + '.'
                elif line_lower.endswith('. reference'):
                    lines[i] = lines[i][:-10]
                elif line_lower.endswith('. reference.'):
                    lines[i] = lines[i][:-11]
                elif line_lower.endswith('. (reference)'):
                    lines[i] = lines[i][:-12]
                elif line_lower.endswith(' (reference).'):
                    lines[i] = lines[i][:-13] + '.'

        return '\n'.join(lines)

    @staticmethod
    def _ident_text(text: str, space_count: int) -> str:
        to_ident = False
        lines = text.split('\n')

        for line in lines[1:]:
            if line != '' and not re.match(r'^\s*((\d+\.\s)|(-\s))', line):
                to_ident = True
                break

        if to_ident:
            for i in range(1, len(lines)):
                if lines[i] != '':
                    lines[i] = ' ' * space_count + lines[i]

            return '\n'.join(lines).strip() + '\n'

        return '\n'.join(lines).strip()

    @staticmethod
    def _fix_list_periods(markdown: str, list_level: int) -> str:
        inside_code = False
        inside_table = False
        relevant_line_indexes = []
        line_lengths = []
        period_count = 0
        lines = markdown.split('\n')
        for i, line in enumerate(lines):
            match = re.match(rf'^ {{{list_level * 4}}}(?:- |\d+\. )(.+)', line)
            if match:
                content = match.group(1)
                if content == '```':
                    inside_code = not inside_code
                elif not inside_table and content.startswith('+') and all(c in {'+', '-'} for c in content):
                    inside_table = True
                elif inside_table and content.startswith('+') and all(c in {'+', '-'} for c in content) and i < len(lines) - 1 and lines[i + 1].strip() == '':
                    inside_table = False
                elif not inside_code and not inside_table and content != '' and not content.startswith('    '):
                    relevant_line_indexes.append(i)
                    line_lengths.append(len(content.split()))
                    if content[-1] in {'.', ',', ':', ';', '?', '!'}:
                        period_count += 1

        average_line_length = sum(line_lengths) / len(line_lengths) if line_lengths else 0
        end_with_period_ratio = period_count / len(line_lengths) if line_lengths else 0
        keep_periods = True if end_with_period_ratio > 0.5 or average_line_length > 10 else False

        for i in relevant_line_indexes:
            if keep_periods:
                if lines[i][-1] not in {'.', ',', ':', ';', '?', '!'} and not lines[i].endswith('and'):
                    lines[i] += '.'
            else:
                if lines[i][-1] == '.':
                    lines[i] = lines[i][:-1]

        return '\n'.join(lines)

    @staticmethod
    def _parse_list_element(list_element: Tag, list_level: int) -> (str, int, int):
        if list_element.name == 'dl' and Parser._is_descendant_of_name(list_element, {'ul', 'ol'}):
            list_level -= 1
        ordered_list_item_count = 1
        items = list_element.find_all(['li', 'dt', 'dd'], recursive=False)
        list_text = ''

        for item_index, item in enumerate(items):
            item_text, list_level = Parser._parse_element(item, list_level)
            item_text = Parser._refine_text(item_text)
            if item_text:
                prefix = ''
                list_text += ' ' * list_level * 4
                if item.name == 'dd':
                    list_text += ' ' * 4
                if item.name == 'li':
                    if list_element.name == 'ol':
                        prefix = f'{ordered_list_item_count}. '
                        ordered_list_item_count += 1
                    else:
                        prefix = '- '
                    list_text += prefix
                list_text += Parser._ident_text(item_text, len(prefix))
                if item_index < len(items) - 1:
                    list_text += '\n'

        if '\n\n' not in list_text:
            list_text = Parser._fix_list_periods(list_text, list_level)

        return list_text, list_level

    @staticmethod
    def _generate_table_from_csv_data(csv_data: str, include_headers: bool = True) -> str:
        # Splitting CSV data into lines
        csv_lines = csv_data.split('\n')

        # Extracting cells and colspans from CSV data
        rows = []
        maximum_number_of_columns = 0
        for csv_line in csv_lines:
            row = []
            current_number_of_columns = 0
            for cell in csv_line.split(','):
                # Reformatting cell and initializing default colspan
                cell = cell.replace('~', ',').replace('\\n', '\n')
                colspan = 1

                # Extracting colspan from cell and updating cell and colspan (if colspan is found)
                match = re.search(r'^(.+)\{colspan-(\d+)}$', cell, re.DOTALL)
                if match:
                    cell = match.group(1)
                    colspan = int(match.group(2))

                # Appending cell and colspan to row list and update row's current number of columns
                row.append((cell, colspan))
                current_number_of_columns += colspan

            # Updating maximum number of columns and appending row list to rows list of lists
            maximum_number_of_columns = max(maximum_number_of_columns, current_number_of_columns)
            rows.append(row)

        if len(rows) == 1:
            include_headers = False

        if len(rows[0]) == 1 and any(len(row) > 1 for row in rows):
            rows[0][0] = (rows[0][0][0], maximum_number_of_columns)

        # Initializing column widths with zeros
        column_widths = [0] * maximum_number_of_columns

        # Calculating and updating column widths based on cells with no colspans (colspan = 1)
        for row in rows:
            for column_index, (cell, colspan) in enumerate(row):
                if colspan == 1:
                    maximum_cell_width = max(len(line) for line in cell.split('\n'))
                    column_widths[column_index] = max(maximum_cell_width, column_widths[column_index])

        # Adjusting column widths (if needed) based on cells with colspans (colspan > 1)
        for row in rows:
            for column_index, (cell, colspan) in enumerate(row):
                if colspan > 1:
                    maximum_cell_width = max(len(line) for line in cell.split('\n'))
                    sum_of_column_widths = sum(column_widths[column_index:column_index + colspan]) + 3 * (colspan - 1)
                    if maximum_cell_width > sum_of_column_widths:
                        missing_width = maximum_cell_width - sum_of_column_widths
                        width_to_add = -(-missing_width // colspan)
                        for i in range(colspan):
                            column_widths[column_index + i] += width_to_add

        # Generating separator based on column widths
        separator = '+' + '+'.join('-' * (width + 2) for width in column_widths) + '+'

        # Initializing table text
        table_text = separator + '\n'

        # Adding text from data rows considering colspans and multiline contents
        for i, row in enumerate(rows):
            # Extracting multiline cells and calculating maximum number of lines in a row
            multi_line_cells = []
            maximum_number_of_lines = 0
            for cell, colspan in row:
                cell_lines = cell.split('\n')
                multi_line_cells.append((cell_lines, colspan))
                maximum_number_of_lines = max(maximum_number_of_lines, len(cell_lines))

            # Adding text for each line in the row
            for line_index in range(maximum_number_of_lines):
                row_text = '|'
                column_index = 0
                for cell_lines, colspan in multi_line_cells:
                    text = cell_lines[line_index].strip() if line_index < len(cell_lines) else ''
                    total_width = sum(column_widths[column_index:column_index + colspan]) + 3 * (colspan - 1)
                    row_text += ' ' + text.ljust(total_width) + ' |'
                    column_index += colspan
                table_text += row_text + '\n'

            # Adding separator after each row
            if i == 0 and include_headers:
                table_text += separator.replace('-', '=')
            else:
                table_text += separator
            if i < len(rows) - 1:
                table_text += '\n'

        return table_text

    @staticmethod
    def _parse_table_element(table_element: Tag, list_level: int) -> tuple[str, int]:
        include_headers = False
        rows = []

        # Extracting rows from table element
        for part_name in ['thead', 'tbody', 'tfoot']:
            part = table_element.find(part_name, recursive=False)
            if part:
                rows += part.find_all('tr', recursive=False)
                if part_name == 'thead':
                    include_headers = True
        rows += table_element.find_all('tr', recursive=False)

        # Extracting data from rows
        csv_data = ''
        for row_index, row in enumerate(rows):
            cell_texts = []
            for cell in row.find_all(['th', 'td'], recursive=False):
                if cell.name == 'th':
                    include_headers = True
                cell_text, list_level = Parser._parse_element(cell, list_level)
                cell_text = cell_text.strip().replace(',', '~').replace('\n', '\\n')
                if cell.has_attr('colspan'):
                    cell_text += f"{{colspan-{cell['colspan']}}}"
                cell_texts.append(cell_text)

            csv_data += ','.join(cell_texts)
            if row_index < len(rows) - 1:
                csv_data += '\n'

        while all(line.startswith(',') for line in csv_data.split('\n')):
            csv_data = '\n'.join(line[1:] for line in csv_data.split('\n'))
        while all(line.endswith(',') for line in csv_data.split('\n')):
            csv_data = '\n'.join(line[:-1] for line in csv_data.split('\n'))

        table_text = Parser._generate_table_from_csv_data(csv_data, include_headers)

        return table_text, list_level

    @staticmethod
    def _is_likely_yaml(text):
        lines = text.strip().splitlines()
        if len(lines) < 5:  # Assuming YAML with less than 5 lines is unlikely
            return False
        yaml_key_pattern = re.compile(r'^([\w|.-]+:).*')
        yaml_list_item_pattern = re.compile(r'^-\s.*')
        for line in lines:
            stripped_line = line.strip()
            if not yaml_key_pattern.match(stripped_line) and not yaml_list_item_pattern.match(stripped_line):
                return False
        return True  # All lines match the YAML pattern

    @staticmethod
    def _handle_code_text(code_text):
        # Attempt to format the entire text block as a single JSON
        try:
            return json.dumps(json.loads(code_text), indent=2)
        except json.JSONDecodeError:
            # If single JSON fails, try to handle concatenated JSON objects
            concatenated_result = Parser._handle_possible_concatenated_json(code_text)
            if concatenated_result:
                return concatenated_result
            # Check if it's reasonable to parse as YAML
            if Parser._is_likely_yaml(code_text):
                try:
                    return dump_yaml(yaml.safe_load(code_text))
                except yaml.YAMLError:
                    # If YAML fails, attempt to fix the YAML formatting
                    fixed_code_text = Parser._fix_yaml(code_text)
                    try:
                        return dump_yaml(yaml.safe_load(fixed_code_text))
                    except yaml.YAMLError:
                        # If fixing the YAML formatting fails, return the original text
                        pass
            # Return original text if it doesn't seem to be JSON, concatenated JSON, or YAML
            return code_text

    @staticmethod
    def _handle_possible_concatenated_json(code_text: str) -> str | None:
        segments = code_text.split('}\n{')
        formatted_segments = []
        segment_parsed = False

        for i, segment in enumerate(segments):
            # Properly bracket each segment
            if i > 0:
                segment = '{' + segment
            if i < len(segments) - 1:
                segment += '}'

            # Attempt to parse and format each segment
            segment_copy = segment
            while True:
                formatted_segment = Parser._format_segment(segment_copy)
                if formatted_segment:
                    formatted_segments.append(formatted_segment)
                    segment_parsed = True
                    break
                else:
                    # If failing and the segment contains '\\', unescape
                    if '\\\\' in segment_copy:
                        segment_copy = segment_copy.replace('\\\\', '\\')
                    else:
                        # If formatting fails, append the original segment
                        formatted_segments.append(segment)
                        break

        return '\n'.join(formatted_segments) if segment_parsed else None

    @staticmethod
    def _format_segment(segment):
        try:
            # First attempt without appending anything
            return json.dumps(json.loads(segment), indent=2)
        except json.JSONDecodeError:
            # Attempt to repair the segment by inserting a '{' at the beginning
            try:
                repaired_segment = '{' + segment
                return json.dumps(json.loads(repaired_segment), indent=2)
            except json.JSONDecodeError:
                # Attempt to repair the segment by appending a '}' at the end
                try:
                    repaired_segment = segment + '}'
                    return json.dumps(json.loads(repaired_segment), indent=2)
                except json.JSONDecodeError:
                    # Attempt to repair the segment by adding both '{' and '}'
                    try:
                        repaired_segment = '{' + segment + '}'
                        return '\n'.join([line[2:] for line in json.dumps(json.loads(repaired_segment), indent=2).splitlines()[1:-1]])
                    except json.JSONDecodeError:
                        return None

    @staticmethod
    def _fix_yaml(text):
        fixed_lines = []
        even_space_prefixes = {}
        for line in reversed(text.splitlines()):
            previous_char = None
            fixed_line = ''
            on_key = False
            collecting_spaces = False
            for char in reversed(line):
                if not on_key and (char == ':' or char == '-') and (previous_char is None or previous_char == ' '):
                    on_key = True
                elif on_key and char == ' ':
                    collecting_spaces = True
                    on_key = False
                elif collecting_spaces and char != ' ':
                    fixed_lines.insert(0, fixed_line.rstrip()[1:])
                    space_prefix = len(fixed_line) - len(fixed_line.lstrip()) - 1
                    if space_prefix > 0 and space_prefix % 2 == 0:
                        if space_prefix not in even_space_prefixes:
                            even_space_prefixes[space_prefix] = 0
                        even_space_prefixes[space_prefix] += 1
                    fixed_line = ''
                    collecting_spaces = False
                fixed_line = char + fixed_line
                previous_char = char
            if fixed_line:
                fixed_lines.insert(0, fixed_line.rstrip())
                space_prefix = len(fixed_line) - len(fixed_line.lstrip())
                if space_prefix > 0 and space_prefix % 2 == 0:
                    if space_prefix not in even_space_prefixes:
                        even_space_prefixes[space_prefix] = 0
                    even_space_prefixes[space_prefix] += 1

        if 2 in even_space_prefixes and 4 not in even_space_prefixes:
            identation = 2
        elif 2 not in even_space_prefixes and 4 in even_space_prefixes:
            identation = 4
        else:
            two_space_sum = 0
            for i in [2, 4, 6]:
                two_space_sum += even_space_prefixes.get(i, 0)
            four_space_sum = 0
            for i in [4, 8, 12]:
                four_space_sum += even_space_prefixes.get(i, 0)

            identation = 2 if two_space_sum > four_space_sum else 4

        last_identation = 0
        for i in range(len(fixed_lines)):
            fixed_line = fixed_lines[i]
            prefix_spaces = len(fixed_line) - len(fixed_line.lstrip())
            if prefix_spaces % identation != 0:
                fixed_lines[i] = ' ' * (last_identation + identation) + fixed_line.lstrip()
            elif fixed_line.endswith(':'):
                last_identation = prefix_spaces

        return '\n'.join(fixed_lines)

    @staticmethod
    def _add_period_or_colon_if_needed(element: Tag, text: str) -> str:
        if not Parser._is_descendant_of_name(element, {'ul', 'ol', 'dl', 'table', 'code'}):
            stripped_last_line = text.split('\n')[-1].strip()
            if stripped_last_line and not re.match(r"^(?:-|[a-zA-Z]\.|[0-9]+\.)|(?:\([a-zA-Z0-9]+\.\)|\([a-zA-Z0-9]+\))", stripped_last_line) and not Parser._is_likely_command(stripped_last_line) and len(stripped_last_line.split()) > 5 and stripped_last_line[-1] not in {'.', ',', ':', ';', '?', '!'}:
                previous_element = Parser._get_previous_outer_element(element)
                if previous_element and previous_element.name in {'b', 'strong'} and Parser._parse_element(previous_element)[0] == stripped_last_line:
                    return text + ':'
                return text + '.'
        return text

    @staticmethod
    def _parse_element(element: Tag, list_level: int = -1, inside_hr: bool = False) -> tuple[str, int]:
        markdown = ""

        for child in element.children:
            if isinstance(child, NavigableString):
                while '\xa0 \xa0' in child:
                    child = child.replace('\xa0 \xa0', '\xa0\xa0')
                clean_string = child.replace('\xa0', ' ').replace('\u200d', '').replace('\t', '')
                if element.name != 'code' and not Parser._is_descendant_of_name(element, 'code'):
                    if clean_string == '\n' or (clean_string == ' ' and (markdown.endswith('\n') or (isinstance(child.previous_sibling, NavigableString) and child.previous_sibling == '\n'))):
                        continue
                    clean_string = re.sub(r'\s+\n', '\n', clean_string)
                    clean_string = re.sub(r'\n\s+', '\n', clean_string)
                if markdown and not markdown.endswith(' ') and clean_string and clean_string.startswith('–'):
                    markdown += ' '
                markdown += clean_string
            elif isinstance(child, Tag):
                if child.name in {'span', 'div'}:
                    recursive_text, list_level = Parser._parse_element(child, list_level, inside_hr)
                    if recursive_text:
                        if 'tooltip' in ' '.join(child.get('class', [])):
                            if recursive_text.endswith('.'):
                                recursive_text = recursive_text[:-1]
                            recursive_text = '(' + recursive_text + ')'
                        if not Parser._is_descendant_of_name(child, 'code') and markdown and markdown[-1] not in {'(', '[', '{', '\n', ' ', '“', '"'} and recursive_text[0] not in {')', ']', '}', '\n', ' ', '”', '"', ':', ';', '*'}:
                            markdown += ' '
                        if child.name == 'div':
                            recursive_text = Parser._add_period_or_colon_if_needed(child, recursive_text)
                        markdown += recursive_text
                        next_element = Parser._get_next_outer_element(child, {'div'})
                        if isinstance(next_element, Tag):
                            if Parser._is_descendant_of_name(child, {'ul', 'ol', 'dl'}) and next_element.name in {'ul', 'ol', 'dl', 'li', 'dt', 'dd'}:
                                markdown += '\n'
                            elif next_element.name in {'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'ul', 'ol', 'img', 'table', 'blockquote'}:
                                markdown += '\n\n'
                elif child.name in {'h1', 'h2', 'h3', 'h4', 'h5', 'h6'}:
                    heading_text, list_level = Parser._parse_element(child, list_level, inside_hr)
                    heading_text = Parser._refine_text(heading_text.replace('\n', ' '))
                    if heading_text:
                        if heading_text.startswith('> '):
                            heading_text = heading_text[2:]
                        if child.get('class', []) == ['tags']:
                            tags_index = heading_text.lower().find('tags: ')
                            heading_text = heading_text[tags_index:] if tags_index != -1 else heading_text
                            markdown += f'{heading_text}\n\n'
                        else:
                            markdown += f'{"#" * int(child.name[1])} {heading_text}\n\n'
                elif child.name == 'p':
                    recursive_text, list_level = Parser._parse_element(child, list_level, inside_hr)
                    recursive_text = Parser._refine_text(recursive_text)
                    if recursive_text:
                        stripped_recursive_text = recursive_text.strip()
                        if not Parser._is_descendant_of_name(child, {'ul', 'ol', 'dl', 'table'}) and not ((recursive_text.count('`') == 2 and stripped_recursive_text.startswith('`') and stripped_recursive_text.endswith('`')) or (recursive_text.count('`') == 6 and stripped_recursive_text.startswith('```') and stripped_recursive_text.endswith('```'))) and not Parser._is_likely_command(stripped_recursive_text) and len(recursive_text.split()) > 5 and recursive_text[-1] not in {'.', ',', ':', ';', '?', '!'} and not recursive_text.startswith('_') and not recursive_text.endswith('_'):
                            recursive_text += '.'
                        markdown += f'{recursive_text}\n'
                        if Parser._is_descendant_of_name(child, {'ul', 'ol', 'dl'}):
                            next_element = Parser._get_next_outer_element(child, {'div', 'ul', 'ol', 'dl', 'li', 'dt', 'dd'})
                        else:
                            next_element = Parser._get_next_outer_element(child, {'div'})
                        if (isinstance(next_element, Tag) and ((not inside_hr and next_element.name != 'p') or (inside_hr and next_element.name not in {'p', 'hr'}))) or (recursive_text.startswith('_') and recursive_text.endswith('_')):
                            markdown += '\n'
                elif child.name == 'em' and element.name == 'p':
                    italic_text, list_level = Parser._parse_element(child, list_level, inside_hr)
                    if italic_text:
                        prefix = ' ' if italic_text.startswith(' ') else ''
                        suffix = ' ' if italic_text.endswith(' ') else ''
                        if Parser._is_descendant_of_name(child, 'blockquote'):
                            mark = ''
                        elif child.text == element.text:
                            mark = '_'
                            suffix += '\n\n'
                        else:
                            mark = "'"
                        markdown += f"{prefix}{mark}{italic_text.strip()}{mark}{suffix}"
                elif child.name == 'hr':
                    markdown += '---\n'
                    if inside_hr:
                        markdown += '\n'
                        inside_hr = False
                    else:
                        inside_hr = True
                elif child.name == 'br':
                    markdown = Parser._add_period_or_colon_if_needed(child, markdown)
                    previous_element = Parser._get_previous_outer_element(child, {'div'})
                    next_element = Parser._get_next_outer_element(child, {'div'})
                    if not (markdown.endswith('\n') or (isinstance(previous_element, NavigableString) and previous_element.endswith('\n')) or (isinstance(next_element, NavigableString) and next_element.startswith('\n'))):
                        markdown += '\n'
                    if isinstance(next_element, Tag) and next_element.name in {'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'ul', 'ol', 'table', 'code', 'blockquote'}:
                        markdown += '\n'
                elif child.name == 'img':
                    if 'data-orig-file' in child.attrs:
                        image_url = child['data-orig-file']
                    elif 'data-lazy-src' in child.attrs:
                        image_url = child['data-lazy-src']
                    elif 'data-src' in child.attrs:
                        image_url = child['data-src']
                    elif 'src' in child.attrs:
                        image_url = child['src']
                    else:
                        image_url = None
                    if image_url:
                        image_url = image_url.replace('\n', '')
                        image_alt_text = child.get('alt', '')
                        if image_alt_text:
                            markdown += f'[Image Info:\n- Alt Text: {image_alt_text}\n{image_url}]\n'
                        else:
                            markdown += f'[Image Info:\n{image_url}]\n'
                        next_element = Parser._get_next_outer_element(child, {'div'})
                        if isinstance(next_element, Tag):
                            if next_element.name in {'figcaption', 'i'}:
                                markdown += '- Caption: '
                            else:
                                markdown += '\n'
                    else:
                        logging.error(f'Could not find image URL for image element: {child}')
                elif child.name in {'caption', 'figcaption', 'i'}:
                    caption_text, list_level = Parser._parse_element(child, list_level, inside_hr)
                    caption_text = Parser._refine_text(caption_text)
                    if caption_text:
                        if caption_text[-1] not in {'.', ',', ':', ';', '?', '!'}:
                            caption_text += '.'
                        markdown += f'{caption_text}\n\n'
                elif child.name in {'ul', 'ol', 'dl'}:
                    list_level += 1
                    list_text, list_level = Parser._parse_list_element(child, list_level)
                    list_level -= 1
                    if list_text:
                        markdown += f'{list_text}\n'
                        next_element = Parser._get_next_outer_element(child, {'div'})
                        if isinstance(next_element, Tag) and next_element.name not in {'ul', 'ol', 'dl', 'li', 'dt', 'dd'}:
                            markdown += '\n'
                elif child.name == 'code':
                    code_text, list_level = Parser._parse_element(child, list_level, inside_hr)
                    code_text = '\n'.join([line.rstrip(' ') for line in code_text.split('\n')]).strip()
                    if code_text:
                        previous_element = Parser._get_previous_outer_element(child, {'div'})
                        previous_li_element = previous_element if previous_element and previous_element.parent == element else None
                        next_element = Parser._get_next_outer_element(child, {'div'})
                        next_li_element = next_element if next_element and next_element.parent == element else None
                        if element.name == 'p' or (element.name in {'li', 'a', 'td'} and ((isinstance(previous_li_element, NavigableString) or isinstance(next_li_element, NavigableString) or (isinstance(previous_li_element, Tag) and (previous_li_element.name == 'code')) or (isinstance(next_li_element, Tag) and (next_li_element.name == 'code'))) or (' ' not in code_text))):
                            markdown += f'`{code_text}`'
                        else:
                            code_text = Parser._handle_code_text(code_text)
                            markdown += f'```\n{code_text}\n```\n'
                            if isinstance(next_element, Tag) and next_element.name == 'i':
                                markdown += 'Code Caption: '
                            else:
                                markdown += '\n'
                elif child.name == 'blockquote':
                    recursive_text, list_level = Parser._parse_element(child, list_level, inside_hr)
                    recursive_text = Parser._refine_text(recursive_text)
                    if recursive_text:
                        markdown += f'> {recursive_text}\n\n'
                elif child.name == 'table':
                    table_text, list_level = Parser._parse_table_element(child, list_level)
                    if table_text:
                        markdown += f'{table_text}\n'
                    next_element = Parser._get_next_outer_element(child, {'div'})
                    if isinstance(next_element, Tag) and next_element.name != 'hr':
                        markdown += '\n'
                elif child.name == 'footer':
                    recursive_text, list_level = Parser._parse_element(child, list_level, inside_hr)
                    if recursive_text:
                        recursive_text = recursive_text.replace('\n', ' ').replace('  ', ' ').strip(' \n|')
                        markdown += f'{recursive_text}\n\n'
                else:
                    recursive_text, list_level = Parser._parse_element(child, list_level, inside_hr)
                    if recursive_text:
                        markdown += recursive_text
                        next_element = Parser._get_next_outer_element(child, {'div'})
                        if isinstance(next_element, Tag) and next_element.name in {'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'dl', 'table', 'blockquote'}:
                            markdown += '\n\n'

        return markdown, list_level

    @staticmethod
    def _reformat_images(markdown: str) -> str:
        for match in re.finditer(r'\[Image Info:\n(- Alt Text: [^\n]+\n)?(https?://\S+)](\n- Caption: [^\n]+)?', markdown):
            alt_text = match.group(1) if match.group(1) else ''
            url = match.group(2) if match.group(2) else ''
            old_caption = match.group(3) if match.group(3) else ''
            new_caption = old_caption[1:] + '\n' if old_caption else ''

            markdown = markdown.replace(f'[Image Info:\n{alt_text}{url}]{old_caption}', f'[Image Info:\n{alt_text}{new_caption}{url}]')

        return markdown

    @staticmethod
    def _fix_headings(markdown):
        headings = re.findall(r'^#+ .+$', markdown, re.MULTILINE)

        hashes_to_balance = len(headings[0].split()[0]) - 1
        if hashes_to_balance > 0:
            for i in range(len(headings)):
                if i == 0:
                    markdown = markdown.replace(headings[i], headings[i][hashes_to_balance:])
                    headings[i] = headings[i][hashes_to_balance:]
                else:
                    markdown = markdown.replace(headings[i], '#' * hashes_to_balance + headings[i])
                    headings[i] = '#' * hashes_to_balance + headings[i]

        levels = [len(heading.split()[0]) for heading in headings]
        if any(level == levels[0] for level in levels[1:]):
            for i in range(1, len(headings)):
                markdown = markdown.replace(headings[i], '#' + headings[i])
                headings[i] = '#' + headings[i]
                levels[i] += 1

        new_levels = levels.copy()
        for i, heading in enumerate(headings):
            for j in range(i - 1, -1, -1):
                if levels[j] < levels[i]:
                    new_levels[i] = new_levels[j] + 1
                    markdown = markdown.replace(heading, '#' * new_levels[i] + ' ' + ' '.join(heading.split()[1:]))
                    break

        return markdown

    @staticmethod
    def _refine_markdown(markdown: str) -> str:
        markdown = Parser._reformat_images(markdown)
        markdown = re.sub(r'\n\s+\n', '\n\n', markdown.strip())
        while '\n\n\n' in markdown:
            markdown = markdown.replace('\n\n\n', '\n\n')
        markdown = Parser._fix_headings(markdown)

        return markdown

    @staticmethod
    def parse_html(html: str, include_images: bool = True) -> str:
        soup = BeautifulSoup(html, 'html.parser')

        logging.info('\t\t\tCleaning HTML')
        Parser._clean_soup(soup)
        logging.info('\t\t\tFixing HTML structure')
        Parser._fix_structure(soup)
        logging.info('\t\t\tFiltering HTML elements')
        Parser._filter_elements(soup, include_images)
        logging.info('\t\t\tParsing HTML')
        markdown, _ = Parser._parse_element(soup)
        logging.info('\t\t\tRefining Markdown')
        markdown = Parser._refine_markdown(markdown)

        # TODO: Handle cases where the last paragraph of the OSCTI is not relevant (e.g. an advertisement or a footer)

        return markdown
