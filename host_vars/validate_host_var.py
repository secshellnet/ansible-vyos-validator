import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from common import check_rules_of_ruleset


def check(file_infos, valid_hosts, **kwargs) -> int:
    """
    Method to check files in the host_vars directory, these contain the firewall rules for the VLANxxx-IN interfaces.
    :param file_infos: infos for file to check
    :param valid_hosts: all hosts which are allowed in jinja patterns
    :return: an int which indicates whether this validator has found any issues
              (0 means no issues found, 1 indicates that we found issues)
    """
    fail = 0
    with open(file_infos["path"]) as f:
        json = yaml.load(f, Loader)

    for family, fam_value in json.items():
        if fam_value is None:
            continue
        for ruleset, rules in fam_value.items():
            if not rules:
                continue
            fail += check_rules_of_ruleset(file_infos, "None", ruleset, rules, valid_hosts,
                                           ruleset not in ["all", "all6"])
    return fail
