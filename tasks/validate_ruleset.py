import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from common import check_duplicate_numbers, check_firewall_rule


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_firewall_rules_module.html
def check_fw_rules(file_infos, json: dict):
    ok = 1
    # check which state the action should use (only one per step)
    if (state := json.get("state")) is None or \
            state not in ["merged", "replaced", "overridden", "deleted", "gathered", "rendered", "parsed"]:
        print(f'  Invalid state={state or "none"}')
        ok = 0

    # the config parameter must be included, otherwise this step isn't functional
    if (config := json.get("config")) is None:
        print('  "config" not found')
        return False

    # check each configured address family (can only be configured one time)
    afis = set()
    for entry in config:
        if (afi := entry.get("afi")) is None or afi not in {"ipv4", "ipv6"} or afi in afis:
            print(f' Invalid afi={afi or "none"}')
        ok = 0
        afis.add(afi)

        if (rule_sets := entry.get("rule_sets")) is None:
            print('  "rule_sets" not found')
            return False
        for ruleset in rule_sets:
            if (name := ruleset.get("name")) is None:
                print(f'  Invalid "ruleset"={name}')
                ok = 0
            if (default_action := ruleset.get("default_action")) is None or \
                    default_action not in ["accept", "drop", "reject"]:
                ok = 0
                print(f'  Invalid "default_action"={default_action and "none"}')
            if (enable_default_log := ruleset.get("enable_default_log")) and \
                    enable_default_log not in [True, False]:
                ok = 0
                print(f'  Invalid "enable_default_log"={enable_default_log}')
            if "rules" not in ruleset:
                print('  rules key does not exists')
                return False
            rules = ruleset["rules"]
            # TODO for rest
            if not rules:
                continue
            # handle VLANxxx-IN interfaces (dynamic configured using host_vars)
            if isinstance(rules, str):
                continue
            ok = min(ok, check_duplicate_numbers(name, rules))
            if name.startswith("WG100-IN"):
                for rule in rules:
                    ok = min(ok, check_firewall_rule(file_infos["site"], afi, name, rule))
    return ok


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_prefix_lists_module.html
def check_prefix_lists(file_infos, json: dict):
    return True


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_logging_global_module.html
def check_logging(file_infos, json: dict):
    return True


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_config_module.html
def check_generic_commands(file_infos, json: dict):
    return True


# https://docs.ansible.com/ansible/latest/collections/vyos/vyos/vyos_firewall_global_module.html
def check_fw_global(file_infos, json: dict):
    return True


def main(file_infos):
    """
    Method to check files in the tasks directory, these contain all firewall
     rules except for the VLANxxx-IN rulesets, which are using by the wireguard
     client peer interfaces (wg100).
    :param filepath: filename of one specific file in the host_vars directory
    :return: a boolean which indicates whether this validator has found any issues
              (True means no issues found, False indicates that we found issues)
    """
    ok = 1
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
            ok = min(ok, check_fw_rules(file_infos, rules))
        elif rules := dictio.get("vyos.vyos.vyos_firewall_global"):
            ok = min(ok, check_fw_global(file_infos, rules))
        elif rules := dictio.get("vyos.vyos.vyos_prefix_lists"):
            ok = min(ok, check_prefix_lists(file_infos, rules))
        elif rules := dictio.get("vyos.vyos.vyos_logging_global"):
            ok = min(ok, check_logging(file_infos, rules))
        elif rules := dictio.get("vyos.vyos.vyos_config"):
            ok = min(ok, check_generic_commands(file_infos, rules))
    return ok
