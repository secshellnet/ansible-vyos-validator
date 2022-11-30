import requests
from re import findall

saved_names: dict[tuple[str, str], list[str]] = {}

def check_duplicate_numbers(name: str, rules: list[dict], key_name: str = "number") -> int:
    """
    This method loops through all rules and stores it's number into a list.
    Afterwards we check if the list contains duplicate numbers
    :param name: ruleset name to print in error strings
    :param rules: list of rule objects
    :param key_name: identifier to use: number for firewall rules, sequence for prefix-lists
    :return: an int which indicates whether this validator has found any issues
              (0 means no issues found, 1 indicates that we found issues)
    """
    numbers = []
    for rule in rules:
        if (number := rule.get(key_name)) is None:
            print(f"  {key_name.capitalize()} missing for \"{name}\": {rule}")
            continue
        numbers.append(number)
    seen = set()
    dups = set()
    for n in numbers:
        if n not in seen:
            seen.add(n)
        else:
            dups.add(n)
    if dups:
        chars = [('', 'is'), ('s', 'are')][len(dups) > 1]
        print(f"  rule{chars[0]} {', '.join(map(str, dups))} {chars[1]} duplicated in ruleset \"{name}\"")
    return len(dups)


def check_cidr(cidr: str, cidr_max: int) -> int:
    if not cidr.isnumeric():
        print(f"  Invalid netmask = {cidr}")
        return 1
    if not 0 <= int(cidr) <= cidr_max:
        print(f"  Invalid ip address = {ip} (netmask out of allowed range")
        return 1
    return 0


def check_ipv4(ip: str) -> int:
    fail = 0
    blocks = ip.split(".")
    if len(blocks) != 4:
        print(f"  Invalid ipv4 address = {ip} (amount of octets)")
        return 1
    for block in blocks:
        if not block.isnumeric():
            print(f"  Invalid ipv4 address = {ip} (octet does not only contain numbers)")
            return 1
        if not 0 <= int(block) <= 255:
            print(f"  Invalid ipv4 address = {ip} (octet > 255)")
            return 1
    return fail


def check_ipv6(ip: str) -> int:
    allowed_chars = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}
    blocks = list(filter(None, ip.split(":")))
    if len(blocks) > 8:
        print(f"  Invalid ipv6 address = {ip} (too many blocks)")
        return 1
    if len(findall(r"(?=(::))", ip)) > 1:
        print(f"  Invalid ipv6 address = {ip} (multiple ::)")
        return 1
    if ip[0] == ":" and ip[1] != ":" or \
            ip[-1] == ":" and ip[-2] != ":":
        print(f"  Invalid ipv6 address = {ip} (invalid format, begins or end with single :)")
        return 1
    for block in blocks:
        if len(block) > 4:
            print(f"  Invalid ipv6 address = {ip} (block > ffff")
            return 1
        if len(set(block.lower()).difference(allowed_chars)) > 0:
            print(f"  Invalid ipv6 address = {ip} (block contains other chars than hex")
            return 1
    return 0


def check_ip(ip: str, require_cidr: bool = False) -> int:
    fail = 0
    if not isinstance(ip, str) or len(ip) == 0:
        print("  Invalid ip address (empty)")
        return 1
    split = ip.split("/")
    if len(split) > 2:
        print(f"  Invalid ip address = {ip} (multiple netmasks")
        return 1
    if len(split) == 2 and not require_cidr:
        print(f"  Invalid ip address = {ip} (netmask not allowed")
        return 1

    if ":" in ip:
        fail += check_ipv6(split[0])
        cidr_max = 128
    else:
        fail += check_ipv4(split[0])
        cidr_max = 32

    if len(split) < 2 and require_cidr:
        print(f"  Invalid ip address = {ip} (netmask required")
    if len(split) == 2:
        if split[1] == "":
            print(f"  Invalid ip address = {ip} (netmask incomplete)")
        fail += check_cidr(split[1], cidr_max)
    return fail


def check_firewall_rule(site: str, afi: str, ruleset_name: str, rule: dict) -> int:
    """
    A method to validate a firewall rule.
    :param site: The site for which this ruleset has been defined (required to get existing source groups from wpm)
    :param afi: Address family of the ruleset (required to get existing source-groups based on ipv4 or ipv6)
    :param ruleset_name: name of ruleset in case of error
    :param rule: the rule object to be validated
    :return: an int which indicates whether this validator has found any issues
              (0 means no issues found, 1 indicates that we found issues)
    """
    if not ruleset_name.startswith("WG100-IN"):
        print(f'  Ruleset "{ruleset_name}" won\'t be handled by the check_firewall_rule method')
        return 0
    numbers = rule.get("number")
    if (ag := rule.get("source", {}).get("group", {}).get("address_group")) is not None:
        return check_source_group(site, afi, ag, numbers, ruleset_name)
    return 0


def check_source_group(site: str, afi: str, source_group_name: dict, rule_number: str, ruleset_name: str) -> int:
    """
    A method to validate that the used source-address groups in wg100 interface
     (which is being configured using wireguard peer manager) exist.
    :param site: The site for which this ruleset has been defined (required to get existing source groups from wpm)
    :param afi: Address family of the ruleset (required to get existing source-groups based on ipv4 or ipv6)
    :param source_group_name: The identifier that is used as address-group.
    :param rule_number: rule number for
    :param ruleset_name: name of ruleset in case of error
    :return: an int which indicates whether this validator has found any issues
              (0 means no issues found, 1 indicates that we found issues)
    """
    if (afi, site) not in saved_names:
        if afi == "ipv4":
            resp = requests.get(f"https://wpm.general.{site}.secshell.net/manage/vyoscli/vpn-source-groups")
        else:
            resp = requests.get(f"https://wpm.general.{site}.secshell.net/manage/vyoscli/vpn-source-groups6")
        if resp.status_code != 200:
            print(f"  Invalid status code while trying to access wpm config for {site}")
            return 1
        saved_names[(afi, site)] = resp.text.split('\n')

    names = saved_names[(afi, site)]
    if source_group_name not in names:
        print(f'  Invalid address-group={source_group_name} used in source of {ruleset_name} rule {rule_number}')
        return 1
    return 0
