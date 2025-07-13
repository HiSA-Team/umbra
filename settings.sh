#!/bin/bash

# Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
#         Salvatore Bramante  <salvatore.bramante@imtlucca.it>
# This file checks for existing dependencies and set up env. variables

###################
# Bash Formatting #
###################

SUCCESS='\033[0;32m'  
WARNING='\033[0;33m'  
FAILURE='\033[0;31m' 
VANILLA='\033[0m'
BOLD='\033[1m' 


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
    echo -e "${FAILURE}Unsupported shell. Please use bash or zsh.${VANILLA}" >&2
    return 1 2>/dev/null || exit 1
fi

echo -e "${SUCCESS}[shell_detection] Running in $SHELL_TYPE shell${VANILLA}"

#############################################################
#    ___                        _             _             #
#   |   \ ___ _ __  ___ _ _  __| |___ _ _  __(_)___ ___     #
#   | |) / -_) '_ \/ -_) ' \/ _` / -_) ' \/ _| / -_|_-<     #
#   |___/\___| .__/\___|_||_\__,_\___|_||_\__|_\___/__/     #
#            |_|                                            #
#############################################################

echo -e '   ___       ___       ___       ___       ___   '
echo -e '  /\__\     /\__\     /\  \     /\  \     /\  \  '
echo -e ' /:/ _/_   /::L_L_   /::\  \   /::\  \   /::\  \ '
echo -e '/:/_/\__\ /:/L:\__\ /::\:\__\ /::\:\__\ /::\:\__\'
echo -e '\:\/:/  / \/_/:/  / \:\::/  / \;:::/  / \/\::/  /'
echo -e ' \::/  /    /:/  /   \::/  /   |:\/__/    /:/  / '
echo -e '  \/__/     \/__/     \/__/     \|__|     \/__/  '
echo -e ""
echo -e "${BOLD}Checking for dependencies${VANILLA}"

# Required dependencies (modify these accordingly to your locations)
export CARGO=cargo
export GCC_PREFIX=arm-none-eabi-
export CC=${GCC_PREFIX}gcc
export LD=${GCC_PREFIX}ld
export OBJDUMP=${GCC_PREFIX}objdump
export OBJCOPY=${GCC_PREFIX}objcopy
export GDB=${GCC_PREFIX}gdb
export GDBGUI=gdbgui
export FLASHER=/Applications/STM32CubeIDE.app/Contents/Eclipse/plugins/com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.macos64_2.2.100.202412061334/tools/bin/STM32_Programmer_CLI
export OPENOCD=openocd

DEPENDENCIES=(
    ${CARGO} 
    ${CC} ${LD} ${OBJDUMP} ${OBJCOPY}
    ${GDB} ${GDBGUI}
    ${FLASHER}
    ${OPENOCD}
)

for dep in "${DEPENDENCIES[@]}"; do
    dep_bin=$(basename "$dep")
    dep_path="${dep%/*}"
    if ! command -v "$dep" &> /dev/null; then
        echo -e "${FAILURE}[dependencies_check] Can't find $dep_bin at $dep_path${VANILLA}, aborting ..." >&2
        return
    else
        echo -e "${SUCCESS}[dependencies_check] Found $dep_bin at $dep_path${VANILLA}"
    fi
done
echo -e ""

#################################################################
#    __  __ _                        _           _ _            #
#   |  \/  (_)__ _ _ ___  __ ___ _ _| |_ _ _ ___| | |___ _ _    #
#   | |\/| | / _| '_/ _ \/ _/ _ \ ' \  _| '_/ _ \ | / -_) '_|   #
#   |_|_ |_|_\__|_| \___/\__\___/_||_\__|_| \___/_|_\___|_|     #
#   / __| ___| |___ __| |_(_)___ _ _                            #
#   \__ \/ -_) / -_) _|  _| / _ \ ' \                           #
#   |___/\___|_\___\__|\__|_\___/_||_|                          #
#                                                               #
#################################################################

# Currently, only STM32L552ZETXQ is supported (and only programming through ST-link)
# In the future, als STM32L562 will be supported, and possibly RISC-V platforms

MCU_CONFIG=$1

echo -e "${BOLD}Selecting target microcontroller${VANILLA}"

##################
# STM32L552ZETXQ #
##################

# This all section shall be enlarged in the future, when support for other boards
# will be added

# Security notes are required.
# The security infrastructure for memory and peripheral is quite rich in st32 MCUs.
# In terms of memory the CPU is protected by the IDAU and the SAU.
# However, transactions that leaves the CPU can be belocked by hardware firewalls.
# The flash memory and the SRAM memories both have protection mechanisms that 
# override CPU memory view. A boot code must enforce the correct memory view
# by configuring all the secure memory controller hierarchy. 

export MCU=stm32l5x2
export OPENOCD_CONFIG=/Users/salvatorebramante/OpenOCD/tcl/board/st_nucleo_l5.cfg
export TARGET_FLASH_START=0x0C000000
export TARGET_ARCH=thumbv8m.main-none-eabi

# ST-LINK command line interface (CLI):
# (https://www.st.com/resource/en/user_manual/um2237-stm32cubeprogrammer-software-description-stmicroelectronics.pdf)

######################
# Flasher Parameters #
######################

# Connection
export PORT_NAME=SWD
export FREQ=4000
export MODE=Normal
export ACCESS_PORT=0
export RESET_MODE=SWrst
export SPEED=Reliable

# Option Bytes (User)
export RDP=0xaa
export BOR_LEV=0x0
export nRST_STOP=0x1
export nRST_STDBY=0x1
export nRST_SHDW=0x1
export IWDG_SW=0x1
export IWDG_STOP=0x1
export IWDG_STDBY=0x1
export WWDG_SW=0x1
export SWAP_BANK=0x0
export DB256=0x1
export DBANK=0x1
export SRAM2_PE=0x1
export SRAM2_RST=0x1
export nSWBOOT0=0x1
export nBOOT0=0x1
export PA15_PUPEN=0x1
export TZEN=0x1
export HDP1EN=0x0
export HDP1_PEND=0x0
export HDP2EN=0x0
export HDP2_PEND=0x0
export NSBOOTADD0=0x100000
export NSBOOTADD1=0x17F200
export SECBOOTADD0=0x180000
export BOOT_LOCK=0x0

# Option Bytes (Flash Security)
# The flash is organized in up to two banks; each bank (256KB) is split into 128 2KB pages.
# It is possible to define two non-volatile secure areas (Watermarked), one per bank, or just one if a 
# single bank (512KB) is used instead. A non-volatile secure area must be aligned to the page size.
# It is possible to dynamically assign security states to single flash pages (in a non-volatile manner).

# A Watermark region size is defined as (PEND-PSTRT)*PSIZE, with PSIZE=2KB
# A Watermark region can be of size 0 if PEND < PSTRT

# Define Watermark region in bank1 (0x08000000) 
export SECWM1_PSTRT=0x0
export SECWM1_PEND=0x7f

# Define Watermark region in bank2 (0x08040000) 
export SECWM2_PSTRT=0x7f
export SECWM2_PEND=0x00

# For each bank, up to two regions can be Write-Protected.
# Same considerations as Watermark region definitions apply.
export WRP1A_PSTRT=0x7f
export WRP1A_PEND=0x0
export WRP1B_PSTRT=0x7f
export WRP1B_PEND=0x0
export WRP2A_PSTRT=0x7f
export WRP2A_PEND=0x0
export WRP2B_PSTRT=0x7f
export WRP2B_PEND=0x0

####################
# Flasher Commands #
####################

export CONNECT="\
        --connect port=${PORT_NAME}\
        freq=${FREQ}\
        reset=${RESET_MODE}\
        mode=${MODE}\
        ap=${ACCESS_PORT}\
        speed=${SPEED}\
        "

export ERASE="\
        --erase all\
        "
# binary path and starting address should be specified in the binary Makefile
export LOAD="\
        --write \
        "

export SECURE_ENABLE="\
        --optionbytes\
        RDP=${RDP}\
        TZEN=${TZEN}\
        "

export OPTION_BYTES="\
        --optionbytes\
        BOR_LEV=${BOR_LEV}\
        nRST_STOP=${nRST_STOP}\
        nRST_STDBY=${nRST_STDBY}\
        nRST_SHDW=${nRST_SHDW}\
        IWDG_SW=${IWDG_SW}\
        IWDG_STOP=${IWDG_STOP}\
        IWDG_STDBY=${IWDG_STDBY}\
        WWDG_SW=${WWDG_SW}\
        SWAP_BANK=${SWAP_BANK}\
        DB256=${DB256}\
        DBANK=${DBANK}\
        SRAM2_PE=${SRAM2_PE}\
        SRAM2_RST=${SRAM2_RST}\
        nSWBOOT0=${nSWBOOT0}\
        nBOOT0=${nBOOT0}\
        PA15_PUPEN=${PA15_PUPEN}\
        HDP1EN=${HDP1EN}\
        HDP1_PEND=${HDP1_PEND}\
        HDP2EN=${HDP2EN}\
        HDP2_PEND=${HDP2_PEND}\
        NSBOOTADD0=${NSBOOTADD0}\
        NSBOOTADD1=${NSBOOTADD1}\
        SECBOOTADD0=${SECBOOTADD0}\
        BOOT_LOCK=${BOOT_LOCK}\
        SECWM1_PSTRT=${SECWM1_PSTRT}\
        SECWM1_PEND=${SECWM1_PEND}\
        SECWM2_PSTRT=${SECWM2_PSTRT}\
        SECWM2_PEND=${SECWM2_PEND}\
        WRP1A_PSTRT=${WRP1A_PSTRT}\
        WRP1A_PEND=${WRP1A_PEND}\
        WRP1B_PSTRT=${WRP1B_PSTRT}\
        WRP1B_PEND=${WRP1B_PEND}\
        WRP2A_PSTRT=${WRP2A_PSTRT}\
        WRP2A_PEND=${WRP2A_PEND}\
        WRP2B_PSTRT=${WRP2B_PSTRT}\
        WRP2B_PEND=${WRP2B_PEND}\
        -ob displ\
        "


# STM32L562E    (TBD)
# Vesuvius      (TBD)

echo -e "${SUCCESS}[mcu_selection]  Selected $MCU${VANILLA}"
echo -e "${SUCCESS}[arch_selection] Selected $TARGET_ARCH${VANILLA}"
echo -e ""

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
    echo -e "${SUCCESS}[path_configuration] $path${VANILLA}"
done

export PATH="$ORIGINAL_PATH"
echo -e ""
#########################
#    _  _        _      #
#   | || |___ __| |_    #
#   | __ / _ (_-<  _|   #
#   |_||_\___/__/\__|   #
#                       #
#########################

echo -e "${BOLD}Configuring Host information${VANILLA}"

# This should be a possible parameter in the future
export HOST_ELF=${ROOT_DIR}/host/bare_metal_arm/bin/bare_metal_arm.elf

echo -e "${SUCCESS}[host_configuration] host elf is @ $HOST_ELF${VANILLA}"
echo -e ""
