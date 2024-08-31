import os
import re
import logging
from datetime import datetime
from typing import List, Optional, Pattern, TextIO, Union
from plugins import DevicePlugin
import json

logger = logging.getLogger(__name__)

def normalize_path(path):
    return os.path.normpath(path).replace("\\", "/")


def apply_clean_lines(lines, clean_lines=False):
    """
    Apply cleaning to lines.

    :param lines: The lines to clean.
    :param clean_lines: The cleaning to apply.
        - If clean_lines is a list, each element in the list will be applied as a separate cleaning.
        - If clean_lines is True, trailing whitespaces will be removed from each line.
        - If clean_lines is "strip", leading and trailing whitespaces will be removed from each line.
        - If clean_lines is "lstrip", leading whitespaces will be removed from each line.
        - If clean_lines is False or not provided, no cleaning will be applied.
        - If clean_lines is a regular expression pattern, it will be used to remove matching patterns from each line.
    :return: The cleaned lines.
    """
    if type(clean_lines) is list:
        for clean_line in clean_lines:
            return apply_clean_lines(lines, clean_line)
    if clean_lines is True:
        return [line.rstrip() for line in lines]
    elif clean_lines == "strip":
        return [line.strip() for line in lines]
    elif clean_lines == "lstrip":
        return [line.lstrip() for line in lines]
    elif clean_lines is False:
        return lines
    elif isinstance(clean_lines, re.Pattern):
        return [re.sub(clean_lines, "", line) for line in lines]
    return lines


def extract_file(
    collection_file: Union[str, TextIO],
    start_regex: Optional[Pattern] = None,
    end_regex: Optional[Pattern] = None,
    start_index_offset: int = 0,
    end_index_offset: int = 0,
    clean_lines: Union[bool, str, Pattern] = True,
) -> List[str]:
    """
    Collect part of a collection file.
    param collection_file: The file to collect from.
    param start_regex: The regex pattern to start collecting from.
    param end_regex: The regex pattern to stop collecting.
    param start_index_offset: The offset to start collecting from.
    param end_index_offset: The offset to stop collecting.
    param clean_lines: Remove white space in lines, rstip by default, if regex, will do line by line.

    return: A list of lines from the file.
    """
    # Handle if collection_file is a path or file-like object

    if isinstance(collection_file, str):
        with open(collection_file, "r") as file:
            lines = file.readlines()
    else:
        collection_file.seek(0)
        lines = collection_file.readlines()

    start_index = 0
    end_index = None
    for index, line in enumerate(lines):
        if start_index and end_index:
            break
        if start_regex and start_regex.search(line):
            start_index = index + start_index_offset
        elif end_regex and end_regex.search(line) and start_index > 0:
            end_index = index - end_index_offset
    selectedlines = apply_clean_lines(
        [str(line) for line in lines[start_index:end_index]], clean_lines
    )

    return selectedlines


def order_folders_by_oldest(folders):
    for folder in folders.copy():
        folder_date = get_date_from_folder(folder)
        if not folder_date:
            logger.warning(
                f"Warning: Folder '{folder}' is not in the expected date format (MMDDYYYY). Using file creation dates."
            )
            folders.remove(folder)
    return sorted(folders, key=lambda x: get_date_from_folder(x))


def get_date_from_folder(folder_name):
    name = os.path.basename(folder_name)
    if re.match(r"\d{8}", name):
        try:
            return datetime.strptime(name, "%m%d%Y").date()
        except ValueError:
            return None


def get_file_creation_date(file_path, folder_date=None):
    if folder_date:
        return folder_date
    return datetime.fromtimestamp(os.path.getctime(file_path)).date()


def parse_folder(args):
    folder = args.folder
    if not os.path.exists(folder):
        raise FileNotFoundError(f"Folder '{folder}' does not exist.")
    return folder


def compile_regex_file(args):
    rxp_file = args.rxp
    rx_lst = [re.compile("^#.*")]
    if os.path.exists(rxp_file):
        with open(rxp_file, "r") as f:
            lines = f.readlines()
        for line in lines:
            try:
                rx_lst.append(re.compile(line.strip()))
            except re.error:
                logger.error(f"Error compiling regex: {line.strip()}")
    else:
        logger.error(
            f"Error: Regex file '{rxp_file}' does not exist...skipping..using default regex"
        )
    return rx_lst


def get_rule_details(plugin: DevicePlugin, rule_name, config):
    """
    Get additional rule details using the plugin's get_rule_details method.

    :param plugin: The plugin instance
    :param rule_name: The name of the rule to get details for
    :return: A dictionary containing the rule details
    """
    try:
        return plugin.get_rule_details(rule_name, config)
    except AttributeError:
        logger.warning("Warning: The plugin does not have a get_rule_details method.")
        return {}


def pack_rule_details(rule_details):
    """
    Pack rule details into a JSON string.

    :param rule_details: A dictionary containing rule details
    :return: A JSON string representation of the rule details
    """
    return json.dumps(rule_details)


def unpack_rule_details(packed_rule_details):
    """
    Unpack a JSON string of rule details into a dictionary.

    :param packed_rule_details: A JSON string containing rule details
    :return: A dictionary of rule details
    """
    return json.loads(packed_rule_details)
