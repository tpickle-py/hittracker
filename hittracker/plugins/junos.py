import re
from plugins import DevicePlugin
from typing import List, Tuple, Optional


class JunosPlugin(DevicePlugin):
    START_CONDITION = r"show security policies hit-count"
    END_CONDITION = r"^$"  # Empty line as end condition
    EXCLUDE_END_LINES = 1  # Exclude last line (e.g., 'Policy count:')

    @classmethod
    def detect_device(cls, output: str) -> bool:
        return bool(re.search(r"show security policies hit-count", output))

    def process_output(self, output: str) -> List[str]:
        unused_policies = []

        for line in output.split("\n"):
            policy = self.define_policy(line)
            if policy:
                _from = policy[0].split()[0]
                _to = policy[0].split()[1]
                _policy_name = policy[0].split()[2]
                _hits = int(policy[1])
                unused_policies.append(
                    (
                        f"from-zone {_from} to-zone {_to} policy-name {_policy_name}",
                        _hits,
                    )
                )
        return unused_policies

    def define_policy(self, line: str) -> Optional[Tuple[str, int]]:
        # return tuple of policy, and hits
        # space delimited columns
        # 'Index' 'From zone' 'To zone' 'Name' 'Policy count'
        # line = re.sub(r"\s+", " ", line).strip()
        match_str = r"\S+\s(\S+\s\S+\s\S+)\s(\S+)"
        match = re.search(match_str, line)
        if match:
            return (match.group(1), int(match.group(2)))
        return None

    def pre_process_output(self, output: str) -> str:
        # removve command
        output = re.sub(r".+show security policies hit-count.+\n", "", output)
        # remove headers
        output = re.sub(
            r"Index\s+From zone\s+To zone\s+Name\s+Policy count", "", output
        )
        # remove duplicate spaces
        output = re.sub(r" +", " ", output)
        return output
