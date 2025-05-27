#!/bin/bash

# Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
#         Salvatore Bramante  <salvatore.bramante@imtlucca.it>
# Description:
#       TBD

source ${SCRIPTS_DIR}/format.sh


if [ -n "$ZSH_VERSION" ]; then
    SHELL_TYPE="zsh"
    # In ZSH, $0 works when sourced and ${0:A} gives the absolute path
    if [[ $ZSH_EVAL_CONTEXT == *:file:* ]]; then
        # Script is being sourced
        SCRIPT_PATH=${${(%):-%x}:A}
    else
        # Script is being executed
        SCRIPT_PATH=${0:A}
    fi
    ROOT_DIR=$(dirname "$SCRIPT_PATH")
elif [ -n "$BASH_VERSION" ]; then
    SHELL_TYPE="bash"
    ROOT_DIR=$(dirname $(realpath ${BASH_SOURCE[0]}))
else
    print_failure "Unsupported shell. Please use bash or zsh." >&2
    return 1 2>/dev/null || exit 1
fi

print_success "[shell_detection] Running in $SHELL_TYPE shell"