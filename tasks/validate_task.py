import yaml
from re import finditer
from json import dumps

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from common import check_rules_of_ruleset


def check_ruleset(ruleset, file_infos, afi, valid_hosts) -> int:
    """
    Method to validate a ruleset
    :param ruleset: 
    :param file_infos: a dictionary with informations regarding the file that is being validated
                       contains for example the site on which the playbook is being ran
    :param afi: the address family of the ruleset (ipv4 or ipv6)
    :param valid_hosts: ???
    :return: the amount of failed checks
    """
    fail = 0
    if (name := ruleset.get("name")) is None:
        print(f'  Invalid "ruleset"={name}')
        fail += 1
    if (default_action := ruleset.get("default_action")) is None or \
            default_action not in ["accept", "drop", "reject"]:
        fail += 1
        print(f'  Invalid "default_action"={default_action and "none"}')
    if (enable_default_log := ruleset.get("enable_default_log")) and \
            enable_default_log not in [True, False]:
        fail += 1
        print(f'  Invalid "enable_default_log"={enable_default_log}')
    if "rules" not in ruleset:
        print(f'  rules key does not exists in ruleset {ruleset}')
        return fail
    rules = ruleset["rules"]
    # TODO for rest
    if not rules:
        return fail
    # handle VLANxxx-IN rulesets (dynamic configured using host_vars)
    if isinstance(rules, str):
        return fail
    fail += check_rules_of_ruleset(file_infos, afi, name, rules, valid_hosts)
    return fail


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_firewall_rules_module.html
def check_fw_rules(file_infos, valid_hosts, json: dict) -> int:
    """
    Method to validate a ruleset
    :param file_infos: a dictionary with informations regarding the file that is being validated
                       contains for example the site on which the playbook is being ran
    :param valid_hosts: ???
    :param json: the configuration data
    :return: the amount of failed checks
    """
    fail = 0
    # check which state the action should use (only one per step)
    if (state := json.get("state")) is None or \
            state not in ["merged", "replaced", "overridden", "deleted", "gathered", "rendered", "parsed"]:
        print(f'  Invalid state={state or "none"}')
        fail = 1

    # the config parameter must be included, otherwise this step isn't functional
    if (config := json.get("config")) is None:
        print(f'  "config" not found in {file_infos["name"]}')
        return fail

    # check each configured address family (can only be configured one time)
    afis = set()
    for entry in config:
        if (afi := entry.get("afi")) is None or afi not in {"ipv4", "ipv6"} or afi in afis:
            print(f' Invalid afi={afi or "none"}')
            fail = 1
        afis.add(afi)

        if (rule_sets := entry.get("rule_sets")) is None:
            print('  "rule_sets" not found')
            return fail
        for ruleset in rule_sets:
            fail += check_ruleset(ruleset, file_infos, afi, valid_hosts)
    return fail


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_prefix_lists_module.html
def check_prefix_lists(file_infos, json: dict) -> int:
    return 0


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_logging_global_module.html
def check_logging(file_infos, json: dict) -> int:
    return 0


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_config_module.html
def check_generic_commands(file_infos, json: dict, valid_hosts: list[str]) -> int:
    fail = 0
    for m in finditer(r"set nat destination rule \d* translation address {{ (.*?) }}", dumps(json)):
        g = m.groups()[0]
        if not g:
            print("  \"\" as nat destination is invalid!")
            fail += 1
        elif g not in valid_hosts:
            print(f"  \"{g}\" as nat destination is not in valid hosts!")
            fail += 1
    return 0


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_firewall_global_module.html
def check_fw_global(file_infos, json: dict) -> int:
    return 0


def check(file_infos, valid_hosts, **kwargs) -> int:
    """
    Method to check files in the tasks' directory, these contain all firewall
     rules except for the VLANxxx-IN rulesets, which are using by the wireguard
     client peer interfaces (wg100).
    :param file_infos: infos for file to check
    :param valid_hosts: all hosts which are allowed in jinja patterns
    :return: a boolean which indicates whether this validator has found any issues
              (True means no issues found, False indicates that we found issues)
    """
    fail = 0
    with open(file_infos["path"]) as f:
        json = yaml.load(f, Loader)
    if not json:
        return 0

    # full list of actions can be found here
    #  https://docs.ansible.com/ansible/latest/collections/vyos/vyos/index.html
    # currently we only use: vyos_firewall_rules, vyos_prefix_lists, vyos_config
    # in the near future we plan to use:
    #  - vyos_logging_global (to configure the syslog daemon)
    #  - vyos_firewall_global (to set static firewall groups)
    for dictio in json:
        if rules := dictio.get("vyos.vyos.vyos_firewall_rules"):
            fail += check_fw_rules(file_infos, valid_hosts, rules)
        elif rules := dictio.get("vyos.vyos.vyos_firewall_global"):
            fail += check_fw_global(file_infos, rules)
        elif rules := dictio.get("vyos.vyos.vyos_prefix_lists"):
            fail += check_prefix_lists(file_infos, rules)
        elif rules := dictio.get("vyos.vyos.vyos_logging_global"):
            fail += check_logging(file_infos, rules)
        elif rules := dictio.get("vyos.vyos.vyos_config"):
            fail += check_generic_commands(file_infos, rules, valid_hosts)
    return fail
