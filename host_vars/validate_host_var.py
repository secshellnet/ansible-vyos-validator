import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from common import check_duplicate_numbers


def main(file_infos) -> bool:
    """
    Method to check files in the host_vars directory, these contain the firewall rules for the VLANxxx-IN interfaces.
    :param filepath: filename of one specific file in the host_vars direcotry
    :return: a boolean which indicates whether this validator has found any issues
              (True means no issues found, False indicates that we found issues)
    """
    ok = 1
    with open(file_infos["path"]) as f:
        json = yaml.load(f, Loader)

    for family, fam_value in json.items():
        if fam_value is None:
            continue
        for ruleset, rules in fam_value.items():
            if not rules:
                continue
            ok = min(ok, check_duplicate_numbers(ruleset, rules))
    return bool(ok)
