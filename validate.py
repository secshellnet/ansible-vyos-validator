from pathlib import Path
from os import environ
from importlib import __import__

ok = 0
p = Path(environ.get("REPO_DIR"))
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

    print(f"Checking {file.relative_to(Path(p))}")
    parent = Path(parent_name)
    # loop through all programs for the file in it's directory
    #  (tasks have other validators than host_vars)
    for prog in parent.glob('**/*'):
        # only accept validators written in python, ignore the init file
        if not (prog.is_file() and prog.name.endswith("py")) or prog.name == "__init__.py":
            continue
        name = prog.name.rstrip('.py')
        module = __import__(f"{parent.name}.{name}")
        if getattr(getattr(module, name), "main"):
            ok = min(ok, getattr(module, name).main(file_infos))

# use the exit status to indicate whether the validator found issues
exit(not bool(ok))
