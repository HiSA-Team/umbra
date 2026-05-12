#!/bin/bash
#
# Force-clear TAMP_BKP[0] via OpenOCD to simulate VBAT power loss
# without physically disconnecting the external 3.3V supply.
#
# Use case: testing the E4P00 fatal halt path of the E.4c oracle.
#
# Prerequisites: openocd in PATH, openocd_scripts/stm32n6x.cfg present,
# board in Flash Boot mode (JP2 1-2) with FSBL halted (debug attached).

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
OPENOCD_CFG="${ROOT_DIR}/openocd_scripts/stm32n6x.cfg"

if [ ! -f "$OPENOCD_CFG" ]; then
    echo "ERROR: $OPENOCD_CFG not found"
    exit 1
fi

echo "=== Simulating VBAT loss (clearing TAMP_BKP[0]) ==="
openocd -f "$OPENOCD_CFG" \
    -c "init" \
    -c "halt" \
    -c "mww 0x56004100 0x00000000" \
    -c "exit"
echo ""
echo "TAMP_BKP[0] cleared. Press RST to trigger E4P00 (plaintext missing)"
echo "or run flash_n657.sh to reflash and recover."
