import re
from typing import List, Tuple

from hittracker.plugins import DevicePlugin
from hittracker.utils import extract_file


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
