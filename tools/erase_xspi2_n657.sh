#!/bin/bash
#
# Erase XSPI2 external flash on NUCLEO-N657X0-Q
#
# Use this to recover the board after flashing an invalid FSBL,
# or to restore the Boot ROM's default clock configuration (150 MHz)
# for GDB debug mode.
#
# Prerequisites:
#   - Board in Dev Boot mode: JP2 (BOOT1) = position 2-3
#   - STM32CubeProgrammer installed

set -e

PROGRAMMER="/Applications/STMicroelectronics/STM32Cube/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/Resources/bin/STM32_Programmer_CLI"
EXT_LOADER="/Applications/STMicroelectronics/STM32Cube/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/Resources/bin/ExternalLoader/MX25UM51245G_STM32N6570-NUCLEO.stldr"

if [ ! -f "$PROGRAMMER" ]; then
    echo "ERROR: STM32_Programmer_CLI not found"
    exit 1
fi

echo "=== Erasing XSPI2 external flash (NUCLEO-N657X0-Q) ==="
echo "    Make sure JP2 (BOOT1) is in position 2-3 (Dev Boot)"
echo ""

# Try HOTPLUG first, fall back to Under Reset
"$PROGRAMMER" \
    -c port=SWD mode=HOTPLUG ap=1 \
    -el "$EXT_LOADER" \
    -e all \
|| \
"$PROGRAMMER" \
    -c port=SWD mode=UR ap=1 \
    -el "$EXT_LOADER" \
    -e all

echo ""
echo "=== XSPI2 erased ==="
echo "Boot ROM will no longer find a valid FSBL on XSPI2."
echo "GDB debug clock should be back to ~150 MHz (115200 baud)."
