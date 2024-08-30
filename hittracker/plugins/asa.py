import re
from typing import List, Tuple

from parsers import cisco_join_parsed_lines
from plugins import DevicePlugin
from utils import extract_file


class AsaPlugin(DevicePlugin):
    def __init__(self):
        self.name = "asa"
        self.command = "show access-list"
        self.device_type = "asa"

    @classmethod
    def detect_device(cls, output: str) -> bool:
        return bool(re.search(r"access-list.*hitcnt=", output))

    def process_output(self, output: str) -> List[Tuple[str, int]]:
        policies = []
        for line in output.split("\n"):
            match = re.search(r"access-list\s+(\S+\s+.*)\(hitcnt=(\d+)", line)
            if match:
                policies.append((match.group(1), int(match.group(2))))
        return policies

    def pre_process_output(self, output: str) -> str:
        # remove command
        output = re.sub(r".+show access-list.+\|.+\n", "", output)
        # remove aces
        output = re.sub(r"  access-list .+\n", "", output)
        # remove line numbers
        output = re.sub(r"line \d+ ", "", output)
        return output

    def extract_output(self, file: str) -> str:
        start_regex = re.compile(r"show access-list")
        end_regex = re.compile(r"(show|exit)")
        start_index_offset = 1
        end_index_offset = 1
        output = extract_file(
            file,
            clean_lines=True,
            start_regex=start_regex,
            end_regex=end_regex,
            start_index_offset=start_index_offset,
            end_index_offset=end_index_offset,
        )
        return output

    def get_rule_details(self, rule: str, config: str) -> dict:
        # Look for the rule in the config and return the lines that match it.
        # Example ACL rule: "access-list outside_access_in line 1 extended permit ip any any"
        # Example ACE rule: "  access-list outside_access_in line 1 extended permit ip any any"
        # Need to search the config using the access-list name and line number, all matches will then be processed out to get the details.

        ret = {
            "Source IPs": "",
            "Destination IPs": "",
            "Source Service": "",
            "Destination Service": "",
            "Action": "",
        }
        # Get the first 4 words of the rule and add wildcard to match the rest of the line
        search_str = re.compile(" ".join(rule.split()[0:4]) + r".+\n")
        matches = search_str.findall(config)
        if not matches:
            return ret
        # convert matches to list and parse the list
        matches = list(map(str, matches))
        return cisco_join_parsed_lines(matches)
