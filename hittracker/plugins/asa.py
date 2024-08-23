# Example plugin (you would create separate files for each device type)
# plugins/asa.py
from hittracker.plugins import DevicePlugin
from typing import List, Tuple
import re

class AsaPlugin(DevicePlugin):
    @classmethod
    def detect_device(cls, output: str) -> bool:
        return bool(re.search(r'access-list.*hitcnt=', output))

    def process_output(self, output: str) -> List[Tuple[str, int]]:
        policies = []
        for line in output.split('\n'):
            match = re.search(r'access-list\s+(\S+)\s+.*hitcnt=(\d+)', line)
            if match:
                policies.append((match.group(1), int(match.group(2))))
        return policies
