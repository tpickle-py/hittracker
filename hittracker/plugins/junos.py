import re
from typing import List, Optional, Tuple

from plugins import DevicePlugin


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
            policy = match.group(1)
            try:
                hits = int(match.group(2))
            except ValueError:
                return None
            return (policy, int(hits))
        return None

    def pre_process_output(self, output: str) -> str:
        # removve command
        output = re.sub(r".+show security policies hit-count.+\n", "", output)
        # remove headers
        output = re.sub(r"Index\s+From zone\s+To zone\s+Name\s+Policy count", "", output)
        # remove duplicate spaces
        output = re.sub(r" +", " ", output)
        return output
        return output


def get_rule_details(self, rule: str, config: str) -> dict:
    # Initialize the return dictionary
    ret = {
        "Source IPs": [],
        "Destination IPs": [],
        "Source Service": [],
        "Destination Service": [],
        "Protocol": [],
        "Action": [],
    }

    # Compile the regex pattern to find the policy rules
    search_str = re.compile(rf"set security policies from-zone .+ to-zone .+ policy {rule} .+\n")
    matches = search_str.findall(config)

    # Compile the regex pattern to find the service definitions
    service_pattern = re.compile(
        r"set applications application (\S+) (protocol \S+|destination-port \S+)\n"
    )
    service_definitions = {}
    for service_match in service_pattern.finditer(config):
        service_name = service_match.group(1)
        service_detail = service_match.group(2)
        if service_name not in service_definitions:
            service_definitions[service_name] = {}
        if "protocol" in service_detail:
            service_definitions[service_name]["protocol"] = service_detail.split()[-1]
        if "destination-port" in service_detail:
            service_definitions[service_name]["port"] = service_detail.split()[-1]

    # If no matches found, return the empty ret dictionary
    if not matches:
        return ret

    # Iterate over each match and extract details
    for match in matches:
        if "match source-address" in match:
            ret["Source IPs"].append(match.split()[-1])
        elif "match destination-address" in match:
            ret["Destination IPs"].append(match.split()[-1])
        elif "match application" in match:
            service_name = match.split()[-1]
            if service_name in service_definitions:
                protocol = service_definitions[service_name].get("protocol", None)
                port = service_definitions[service_name].get("port", None)
                if protocol:
                    ret["Destination Service"].append(f"{protocol}/{port}")

        elif "then permit" in match:
            ret["Action"].append("permit")
        elif "then deny" in match:
            ret["Action"].append("deny")
        elif "then log session-init" in match:
            ret["Action"].append("log session-init")
        elif "then log session-close" in match:
            ret["Action"].append("log session-close")

    # Remove trailing commas and spaces
    for key in ret.keys():
        ret[key] = ";".join(ret[key])

    return ret
