#!/bin/bash

# check if pip is installed

if ! which ansible-lint &> /dev/null; then
  if ! which python3 &> /dev/null; then
    echo "python3 is not installed, exiting..."
    exit 1
  fi
  python3 -m pip install "ansible-lint"
fi

ansible-lint -x comments
