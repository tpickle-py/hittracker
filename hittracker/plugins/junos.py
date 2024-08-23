import re
from plugins import DevicePlugin
from typing import List, Tuple, Optional

class JunosPlugin(DevicePlugin):
    START_CONDITION = r'^Policy:'
    END_CONDITION = r'^$'  # Empty line as end condition
    EXCLUDE_END_LINES = 1  # Exclude last line (e.g., 'Policy count:')

    @classmethod
    def detect_device(cls, output: str) -> bool:
        return bool(re.search(r'Policy:.*hit-count:', output))

    def process_output(self, output: str) -> List[str]:
        unused_policies = []
        filtered_lines = self.filter_output_lines(output)
        for line in filtered_lines:
            policy = self.define_policy(line)
            if policy and policy[1] == 0:
                unused_policies.append(policy[0])
        return unused_policies

    def define_policy(self, line: str) -> Optional[Tuple[str, int]]:
        # return tuple of policy, and hits
        # space delimited columns
        # 'Index' 'From zone' 'To zone' 'Name' 'Policy count'
        line = re.sub(r'\s+', ' ', line).strip()
        match_str = r'\S+\s(\S+\s\S+\s\S+)\s(\S+)'
        match = re.search(match_str, line)
        if match:
            return (match.group(1), int(match.group(2)))
        return None