#!/bin/bash

# Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
#         Salvatore Bramante  <salvatore.bramante@imtlucca.it>
# This file checks for existing dependencies and set up env. variables


echo -e '   ___       ___       ___       ___       ___   '
echo -e '  /\__\     /\__\     /\  \     /\  \     /\  \  '
echo -e ' /:/ _/_   /::L_L_   /::\  \   /::\  \   /::\  \ '
echo -e '/:/_/\__\ /:/L:\__\ /::\:\__\ /::\:\__\ /::\:\__\'
echo -e '\:\/:/  / \/_/:/  / \:\::/  / \;:::/  / \/\::/  /'
echo -e ' \::/  /    /:/  /   \::/  /   |:\/__/    /:/  / '
echo -e '  \/__/     \/__/     \/__/     \|__|     \/__/  '
echo -e ""
echo -e "${BOLD}Checking for dependencies${VANILLA}"

source scripts/format.sh
source scripts/shell.sh

#############################
#    ___      _   _         #
#   | _ \__ _| |_| |_  ___  #
#   |  _/ _` |  _| ' \(_-<  #
#   |_| \__,_|\__|_||_/__/  #
#                           #
#############################

echo -e "${BOLD}Configuring paths${VANILLA}"

# Real path is required to avoid problems with relative paths
ORIGINAL_PATH="$PATH"

# Configure platform target
# ROOT_DIR is now defined at the beginning of the script based on shell type
export LIB_DIR="${ROOT_DIR}/lib"
export HW_DIR="${ROOT_DIR}/src/hardware"
export KERNEL_DIR="${ROOT_DIR}/src/kernel"
export SCRIPTS_DIR="${ROOT_DIR}/scripts"
export PLATFORM_DIR="${HW_DIR}/platform/${MCU}"
export DRIVER_DIR="${PLATFORM_DIR}/driver"
export SECBOOT_DIR="${PLATFORM_DIR}/boot"
export PLATFORM_LD_DIR="${PLATFORM_DIR}/linker"

export PATH="$ORIGINAL_PATH"

CONFIG_PATHS=(
    "${ROOT_DIR}" \
    "${LIB_DIR}" \
    "${HW_DIR}" \
    "${PLATFORM_DIR}" \
    "${DRIVER_DIR}" \
    "${SECBOOT_DIR}" \
    "${PLATFORM_LD_DIR}" \
    "${KERNEL_DIR}" \
)

for path in "${CONFIG_PATHS[@]}"; do
    print_success "[path_configuration] $path"
done

export PATH="$ORIGINAL_PATH"
echo -e ""


#############################################################
#    ___                        _             _             #
#   |   \ ___ _ __  ___ _ _  __| |___ _ _  __(_)___ ___     #
#   | |) / -_) '_ \/ -_) ' \/ _` / -_) ' \/ _| / -_|_-<     #
#   |___/\___| .__/\___|_||_\__,_\___|_||_\__|_\___/__/     #
#            |_|                                            #
#############################################################

