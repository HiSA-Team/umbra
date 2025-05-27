#!/bin/bash

# Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
# Description:
#       This file defines the environmental variables used for the project.
#       By default we assume all the critical tools to be in user PATH.
#       If not, the script tries to identify them automatically.

source ${SCRIPTS_DIR}/format.sh

# Required dependencies (modify these accordingly to your locations)
# Currently, we assume the toolchain to be GCC, the Backend to be Openocd.
export CARGO=cargo
export GCC_PREFIX=arm-none-eabi-
export BACKEND=openocd

export CC=${GCC_PREFIX}gcc
export LD=${GCC_PREFIX}ld
export OBJDUMP=${GCC_PREFIX}objdump
export OBJCOPY=${GCC_PREFIX}objcopy
export GDB=${GCC_PREFIX}gdb

DEPENDENCIES=(
    ${CARGO} 
    ${CC} ${LD} ${OBJDUMP} ${OBJCOPY}
    ${GDB}
    ${BACKEND}
)

for dep in "${DEPENDENCIES[@]}"; do
    dep_bin=$(basename "$dep")
    dep_path="${dep%/*}"
    if ! command -v "$dep" &> /dev/null; then
        print_failure "[dependencies_check] Can't find $dep_bin at $dep_path, aborting ..." >&2
        return
    else
        print_success "[dependencies_check] Found $dep_bin at $dep_path"
    fi
done
echo -e ""