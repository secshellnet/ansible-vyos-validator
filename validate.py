from importlib import __import__
from os import environ
from common import check_ip
import yaml
from pathlib import Path

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

valid_hosts: list[str] = []
p = Path(environ.get("REPO_DIR"))


def check_file(file_infos, file, p) -> int:
    fail = 0
    print(f"Checking {file.relative_to(Path(p))}")
    parent = Path(file_infos["parent_name"])
    # loop through all programs for the file in its directory
    #  (tasks have other validators than host_vars)
    for prog in parent.glob('**/*'):
        # only accept validators written in python, ignore the init file
        if not (prog.is_file() and prog.name.endswith("py")) or prog.name == "__init__.py":
            continue
        name = prog.name.rstrip('.py')
        module = __import__(f"{parent.name}.{name}")
        if getattr(getattr(module, name), "check", None):
            fail += getattr(module, name).check(file_infos)
    return fail


def check_files() -> int:
    fail = 0
    for file in p.rglob('*'):
        # find all files that should be checked
        if not (file.is_file() and (file.name.endswith("yaml") or file.name.endswith("yml"))):
            continue

        # currently we only want to validate files in the subdirectories tasks and host_vars
        parent_name = ""
        for folder in ["host_vars", "tasks"]:
            if folder in file.parts:
                parent_name = folder
                break
        if not parent_name:
            continue

        file_infos = {}
        if file.parent.name == "tasks":
            file_infos["site"] = "all"
        elif file.parent.name == "host_vars":
            pass
        else:
            file_infos["site"] = file.parent.name
        file_infos["path"] = file.absolute()
        file_infos["name"] = file.name
        file_infos["parent_name"] = parent_name

        fail += check_file(file_infos, file, p)

    return fail


def traverse_dict(path: str, dictio: dict) -> tuple[int, list[str]]:
    lst: list[str] = []
    fail = 0
    for key, value in dictio.items():
        if isinstance(value, dict):
            ret = traverse_dict(f"{path}.{key}", value)
            fail += ret[0]
            lst += ret[1]
        else:
            if path[:2] == "v6" and path.count(".") == 1:
                print(f"  Invalid configuration ipv6 address={ip} configured on device, make it a named address")
                fail = 1
            require_cidr = any(f in key for f in ["_vpn", "_net"])
            fail += check_ip(value, require_cidr)
            lst += [f"{path}.{key}"]
    return fail, lst


def check_hosts() -> int:
    global valid_hosts
    fail = 0
    lst: list[str] = []
    with open(p.joinpath("hosts.yml")) as f:
        json = yaml.load(f, Loader)
    print("Checking hosts.yml")
    if (dictio := json.get("all", {}).get("vars", {})) is None:
        print(f"  Invalid hosts.yaml, no vars defined.")
        return 1
    for afi in ["v4", "v6"]:
        if (hosts := dictio.get(afi)) is None:
            continue
        ret = traverse_dict(afi, hosts)
        fail += ret[0]
        lst += ret[1]
    valid_hosts = lst
    return fail


def main() -> int:
    return check_hosts() + check_files()


if __name__ == '__main__':
    num_errors = main()
    print("\nWe found a total of {num_errors} errors!!!")
    # use the exit status to indicate whether the validator found issues
    exit(max(1, num_errors))
