# ansible-vyos-validator

This repository contains a simple python alpine docker image 
to validate some easy to make mistakes in 
[ansible-vyos](https://docs.ansible.com/ansible/latest/collections/vyos/vyos/index.html)
We use it for the continuous integration with [woodpecker](https://woodpecker-ci.org/) in our internal gitea.

I decided to make this project public, even though it contains some internal details, for educational purpose.
You won't be able to directly use this image yourself!

Currently, it supports checking the 
[existence of source address-group's](https://github.com/secshellnet/ansible-vyos-validator/blob/main/common.py#L55-L81) 
using an api from [wireguard peer manager](https://github.com/felbinger/WPM) and detection of 
[duplicated usage of rule numbers](https://github.com/secshellnet/ansible-vyos-validator/blob/main/common.py#L7-L33)
inside one ruleset (which would overwrite the first one).

Thank you [@TheCataliasTNT2k](https://github.com/thecataliastnt2k) for the python implementation of this project.

## How we did it before
Until we decided to build this tool, we used the following bash scripts to verify the changes are ok:
```shell
#!/bin/bash

# this script checks if a ansible-vyos firewall ruleset task contains
# duplicate rule numbers to ensure the integrity of the rules

# abort on first uncatched error
set -e

filename=${1}

if [ -z ${filename} ]; then
  echo "Usage ./${0} path/to/task.yml"
  exit 1
fi

actual=$(yq '.[]."vyos.vyos.vyos_firewall_rules" | select(. != null) | .config[].rule_sets | select(. != null) | .[].rules | select(. != null)' ${filename})
unique=$(yq 'select(. != null) | unique_by(.number)' <<< ${actual})
actual_size=$(yq '.[].number' <<< ${actual} | wc -l)
unique_size=$(yq '.[].number' <<< ${unique} | wc -l)

if [ ${actual_size} -ne ${unique_size} ]; then
  delta --side-by-side <(yq <<< ${unique}) <(yq <<< ${actual})
  exit 1
fi

exit 0
```

```shell
#!/bin/bash

# this script checks if a ansible-vyos firewall ruleset task uses
# address-groups which have note been defined in wireguard peer manager

# abort on first uncatched error
set -e

# filename format is fw-RULESET-SITE-ADDR_FAMILY.yml
filename=${1}

if [[ ! "${filename}" =~ "wg100" ]]; then
  # workflow run not required
  exit 0
fi

if [ -z ${filename} ]; then
  echo "Usage ./${0} path/to/task.yml"
  exit 1
fi

# for each rule check if source element is configured, for those that have it configured, add the address_group to the array
_used_source_groups=$(yq -o json '[.[]."vyos.vyos.vyos_firewall_rules" | select(. != null) | .config[] | select(. != null) | .rule_sets[].rules[].source | select(. != null) | .group.address_group | select(. != null)] | unique' < ${filename})
used_source_groups=($(jq -r '.[]' <<< ${_used_source_groups}))

# check if at least one source group is being used (if not then this check is not reqeuired)
if [[ ${#used_source_groups[@]} -eq 0 ]]; then
  exit 0
fi

# get existing source groups from wireguard peer manager
site=$(basename ${filename} | cut -d- -f2)
if [[ "${filename}" =~ "v4" ]]; then
  existing_source_groups=($(curl -fsSL https://wpm.general.${site}.secshell.net/manage/vyoscli/vpn-source-groups | sort))
else
  existing_source_groups=($(curl -fsSL https://wpm.general.${site}.secshell.net/manage/vyoscli/vpn-source-groups6 | sort))
fi

for source_group in ${used_source_groups[@]}; do
  if [[ ${existing_source_groups[@]} =~ ${source_group} ]]; then
    continue
  fi
  delta --side-by-side <(for elem in ${used_source_groups[@]}; do echo ${elem}; done) <(for elem in ${existing_source_groups[@]}; do echo ${elem}; done)
  exit 1
done

exit 0
```
