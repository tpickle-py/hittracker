import logging
import re

logger = logging.getLogger(__name__)

pat_inactive_acl = r" inactive | \(inactive\) "
re_inactive_acl = re.compile(pat_inactive_acl)

ip6 = str("0000:" * 8).rstrip(":")
ipv6 = f"{ip6} {ip6}"


def sub_any(item):
    item = re.sub(r"any|any4", "0.0.0.0 0.0.0.0", item)
    item = re.sub(
        r"any6",
        f"{ipv6} {ipv6}",
        item,
    )
    return item


def validate_ipv6(ip_addr):
    # Regex expression for validating IPv6

    ipv6_short = r"(((([a-f]|[0-9]){1,4})|:{1,}):{1,}){4,}/\d+"
    ipv6_long = (
        r"\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
        + r"(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
        + r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
        + r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
        + r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
        + r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
        + r"[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})"
        + r"|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)"
        + r"|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}"
        + r"|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]"
        + r"|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]"
        + r"|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
        + r"|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]"
        + r"|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]"
        + r"|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
        + r"(?:\/(?:[0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?\b"
    )

    re_ipv6_short = re.compile(ipv6_short)
    re_ipv6_long = re.compile(ipv6_long)

    # Checking if it is a valid IPv6 addresses
    if re.search(re_ipv6_long, ip_addr) or re.search(re_ipv6_short, ip_addr):
        # logger.debug(f"IPv6 address {ip_addr} is valid")
        return True
    return False


class Rule:
    "Class for an ACL rule"

    # access-list myacl remark My best rule
    re_hitcnt = re.compile(r"\(hitcnt=(?P<hit>\d+)\)\s+(?P<hash>\w+)\s+$", re.IGNORECASE)
    re_ace = re.compile(r"^\s+access-list\s\S+.+extended.*$", re.IGNORECASE)
    re_acl = re.compile(r"^access-list\s\S+.+extended.*$", re.IGNORECASE)
    re_acl_rem = re.compile(r"^\s*access-list\s+\S+\s+remark\s+(?P<acl_rem>.*$)", re.IGNORECASE)
    re_line_num = re.compile(r"line\s(?P<num>\d+)", re.IGNORECASE)
    re_standard_ace = re.compile(
        r"^\s*access-list\s+\S+\s+standard\s+(?P<acl_std>.*$)", re.IGNORECASE
    )
    re_ip = (
        r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
        + r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    )
    # All subsequent remarks are concatenated in this persistent variable
    remark = ""

    def __init__(self, line):
        self.acl = line
        self.line = line
        self.name = ""
        self.src = None
        self.dst = None
        self.src_port = None
        self.port = None
        self.proto = None
        self.action = None
        self.num = None
        if Rule.re_ace.search(line) or Rule.re_acl.search(line):
            self.cleanup()
            self.rem = ""
            self.parse()
        else:
            pass
        self.line = self.line.strip()

    def delimit(self):
        arr = self.line.split()
        # ACL name
        self.name = arr[1]
        # Permit or deny
        self.action = arr[3]
        del arr[0:4]
        # port protocol
        if "object-group" in arr[0]:  # pragma: no cover
            self.port = arr[1]
            del arr[0:2]
        elif "object" in arr[0]:
            self.port = arr[1]
            del arr[0:2]
        else:
            self.proto = arr[0]
            del arr[0]
        # Source
        if "object-group" in arr[0]:
            self.src = arr[1]
            del arr[0:2]
        elif "object" in arr[0]:  # pragma: no cover
            self.src = arr[1]
            del arr[0:2]
        elif "host" in arr[0]:
            self.src = arr[1]
            del arr[0:2]
        elif "range" in arr[0]:  # pragma: no cover
            self.src = f"{arr[1]}-{arr[2]}"
            del arr[0:3]
        else:  # pragma: no cover
            self.src = f"{arr[0]} {arr[1]}"
            del arr[0:2]
        # Source ports
        # print(self.line)
        if "range" in arr[0]:  # pragma: no cover
            # test for ip
            regex_ip = re.match(Rule.re_ip, arr[1])
            if not regex_ip:
                self.src_port = f"{arr[1]}-{arr[2]}"
                del arr[0:3]
        if "eq" in arr[0] or "lt" in arr[0] or "gt" in arr[0] or "neq" in arr[0]:
            self.src_port = f"{arr[0]} {arr[1]}"
            del arr[0:2]
        # Destination
        if "object-group" in arr[0]:
            self.dst = arr[1]
            del arr[0:2]
        elif "object" in arr[0]:  # pragma: no cover
            self.dst = arr[1]
            del arr[0:2]
        elif "host" in arr[0]:  # pragma: no cover
            self.dst = arr[1]
            del arr[0:2]
        elif "range" in arr[0]:  # pragma: no cover
            self.dst = f"{arr[1]}-{arr[2]}"
            del arr[0:3]
        else:
            self.dst = f"{arr[0]} {arr[1]}"
            del arr[0:2]
        # Services
        if len(arr) > 0:  # pragma: no cover
            if "object-group" in arr[0]:
                self.port = arr[1]
            else:
                self.port = " ".join(arr[:])
        elif not self.port:  # pragma: no cover
            self.port = self.proto

    # Simple clean-up
    def cleanup(self):  # pragma: no cover
        self.line = re.sub(r"\s+log$|\s+log\s+.*$", "", self.line)
        # self.line=re.sub(r'\bany\b|\bany4\b','0.0.0.0 0.0.0.0',self.line)
        if Rule.re_line_num.search(self.line):
            self.num = Rule.re_line_num.search(self.line).group("num")
            self.line = re.sub(r"\sline\s\d+", "", self.line)
        if Rule.re_ace.search(self.line):
            self.type = "ACE"

        elif Rule.re_acl.search(self.line):
            self.type = "ACL"
        self.line = re.sub(r"\s\(hitcnt=\d+\)", "", self.line)
        self.line = re.sub(r"\s+0x\w+\s+$", "", self.line)

    def parse(self):
        if Rule.re_ace.search(self.line) or Rule.re_acl.search(self.line):
            self.delimit()


def parse_cisco_line(line):
    # print(line)
    sed = re.sub(r"\< |\> ", "", line)
    ret = {
        "Source IP": "",
        "Destination IP": "",
        "Source Service": "",
        "Destination Service": "",
        "Action": "",
    }
    try:
        obj = Rule(sed)
        if obj.src:
            ret["Source IP"] = sub_any(obj.src)
            ret["Destination IP"] = sub_any(obj.dst)
            ret["Source Service"] = f"{obj.proto.upper()}/{obj.src_port}" if obj.src_port else None
            ret["Destination Service"] = f"{obj.proto.upper()}/{obj.port}" if obj.port else None
            ret["Action"] = obj.action
        return ret

    except Exception as e:  # pragma: no cover
        logger.error(e, exc_info=True)
        logger.error(f"Issue in : {line}")
        return ret


def cisco_join_parsed_lines(parsed_lines):
    ret = {
        "Source IP": [],
        "Destination IP": [],
        "Source Service": [],
        "Destination Service": [],
        "Action": [],
    }
    for line in parsed_lines:
        if not line:
            continue
        details = parse_cisco_line(line)
        if details["Action"]:
            for key in details.keys():
                ret[key].append(details[key])
    for key in ret.keys():
        ret[key] = list(set(ret[key]))
        ret[key] = ";".join(ret[key])
    return ret
