import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from common import check_duplicate_numbers, check_firewall_rule


def check_ruleset(ruleset, file_infos, afi) -> int:
    fail = 0
    if (name := ruleset.get("name")) is None:
        print(f'  Invalid "ruleset"={name}')
        fail = 1
    if (default_action := ruleset.get("default_action")) is None or \
            default_action not in ["accept", "drop", "reject"]:
        fail = 1
        print(f'  Invalid "default_action"={default_action and "none"}')
    if (enable_default_log := ruleset.get("enable_default_log")) and \
            enable_default_log not in [True, False]:
        fail = 1
        print(f'  Invalid "enable_default_log"={enable_default_log}')
    if "rules" not in ruleset:
        print(f'  rules key does not exists in ruleset {ruleset}')
        return 1
    rules = ruleset["rules"]
    # TODO for rest
    if not rules:
        return 0
    # handle VLANxxx-IN interfaces (dynamic configured using host_vars)
    if isinstance(rules, str):
        return 0
    fail = max(fail, check_duplicate_numbers(name, rules))
    if name.startswith("WG100-IN"):
        for rule in rules:
            fail = max(fail, check_firewall_rule(file_infos["site"], afi, name, rule))
    return fail


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_firewall_rules_module.html
def check_fw_rules(file_infos, json: dict) -> int:
    fail = 0
    # check which state the action should use (only one per step)
    if (state := json.get("state")) is None or \
            state not in ["merged", "replaced", "overridden", "deleted", "gathered", "rendered", "parsed"]:
        print(f'  Invalid state={state or "none"}')
        fail = 1

    # the config parameter must be included, otherwise this step isn't functional
    if (config := json.get("config")) is None:
        print(f'  "config" not found')
        return 1

    # check each configured address family (can only be configured one time)
    afis = set()
    for entry in config:
        if (afi := entry.get("afi")) is None or afi not in {"ipv4", "ipv6"} or afi in afis:
            print(f' Invalid afi={afi or "none"}')
        fail = 1
        afis.add(afi)

        if (rule_sets := entry.get("rule_sets")) is None:
            print('  "rule_sets" not found')
            return 1
        for ruleset in rule_sets:
            fail = max(fail, check_ruleset(ruleset, file_infos, afi))
    return fail


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_prefix_lists_module.html
def check_prefix_lists(file_infos, json: dict) -> int:
    return 0


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_logging_global_module.html
def check_logging(file_infos, json: dict) -> int:
    return 0


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_config_module.html
def check_generic_commands(file_infos, json: dict) -> int:
    return 0


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_firewall_global_module.html
def check_fw_global(file_infos, json: dict) -> int:
    return 0


def check(file_infos) -> int:
    """
    Method to check files in the tasks directory, these contain all firewall
     rules except for the VLANxxx-IN rulesets, which are using by the wireguard
     client peer interfaces (wg100).
    :param file_infos: infos for file to check
    :return: a boolean which indicates whether this validator has found any issues
              (True means no issues found, False indicates that we found issues)
    """
    fail = 0
    with open(file_infos["path"]) as f:
        json = yaml.load(f, Loader)
    if not json:
        return True

    # full list of actions can be found here
    #  https://docs.ansible.com/ansible/latest/collections/vyos/vyos/index.html
    # currently we only use: vyos_firewall_rules, vyos_prefix_lists, vyos_config
    # in the near future we plan to use:
    #  - vyos_logging_global (to configure the syslog daemon)
    #  - vyos_firewall_global (to set static firewall groups)
    for dictio in json:
        if rules := dictio.get("vyos.vyos.vyos_firewall_rules"):
            fail = max(fail, check_fw_rules(file_infos, rules))
        elif rules := dictio.get("vyos.vyos.vyos_firewall_global"):
            fail = max(fail, check_fw_global(file_infos, rules))
        elif rules := dictio.get("vyos.vyos.vyos_prefix_lists"):
            fail = max(fail, check_prefix_lists(file_infos, rules))
        elif rules := dictio.get("vyos.vyos.vyos_logging_global"):
            fail = max(fail, check_logging(file_infos, rules))
        elif rules := dictio.get("vyos.vyos.vyos_config"):
            fail = max(fail, check_generic_commands(file_infos, rules))
    return fail
