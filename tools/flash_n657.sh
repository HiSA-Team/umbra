#!/bin/bash
#
# Flash Umbra as FSBL to NUCLEO-N657X0-Q external flash (XSPI2)
#
# Prerequisites:
#   1. source ./settings.sh (with MCU_VARIANT=stm32n657)
#   2. Board in Dev Boot mode: JP2 (BOOT1) = position 2-3
#   3. STM32CubeProgrammer installed
#
# After flashing:
#   1. Set JP2 (BOOT1) = position 1-2 (Flash Boot)
#   2. Reset board → Boot ROM loads Umbra from XSPI2
#   3. UART at 115200 baud shows boot banner
#
# For GDB debug after FSBL boot:
#   openocd -f ./openocd_scripts/stm32n6x.cfg
#   arm-none-eabi-gdb <elf> -ex 'target extended-remote:3333'

set -eo pipefail

# Paths
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
BOOT_DIR="${ROOT_DIR}/src/hardware/platform/stm32n657/boot"
BOOT_ELF="${BOOT_DIR}/target/thumbv8m.main-none-eabi/release/boot"
BOOT_BIN="${BOOT_DIR}/target/thumbv8m.main-none-eabi/release/boot.bin"
FSBL_TRUSTED="${BOOT_DIR}/target/thumbv8m.main-none-eabi/release/boot-trusted.bin"

# Tools — STM32CubeProgrammer install root. Override via env var, e.g. on Linux:
#   export STM32CUBE_PROG_DIR=/opt/st/stm32cubeprog/bin
# Or override individual tool paths via STM32_SIGNING_TOOL / STM32_PROGRAMMER /
# STM32_EXT_LOADER_N657 for installs that don't follow the standard layout.
STM32CUBE_PROG_DIR="${STM32CUBE_PROG_DIR:-/Applications/STMicroelectronics/STM32Cube/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/Resources/bin}"
SIGNING_TOOL="${STM32_SIGNING_TOOL:-$STM32CUBE_PROG_DIR/STM32_SigningTool_CLI}"
PROGRAMMER="${STM32_PROGRAMMER:-$STM32CUBE_PROG_DIR/STM32_Programmer_CLI}"
EXT_LOADER="${STM32_EXT_LOADER_N657:-$STM32CUBE_PROG_DIR/ExternalLoader/MX25UM51245G_STM32N6570-NUCLEO.stldr}"
OBJCOPY="${GCC_PREFIX:-arm-none-eabi-}objcopy"

# Check tools exist
for tool in "$SIGNING_TOOL" "$PROGRAMMER" "$EXT_LOADER"; do
    if [ ! -f "$tool" ]; then
        echo "ERROR: Not found: $tool"
        exit 1
    fi
done

if ! command -v "$OBJCOPY" &>/dev/null; then
    echo "ERROR: $OBJCOPY not found in PATH"
    exit 1
fi

# Check ELF exists
if [ ! -f "$BOOT_ELF" ]; then
    echo "ERROR: Boot ELF not found. Run: cd $BOOT_DIR && cargo build --release"
    exit 1
fi

echo "=== STM32N657 FSBL Flash Tool (Path B-lite — plaintext flash) ==="
echo ""
# Phase E.4c (MCE2 encryption-at-rest) is DEFERRED — see boot crate's
# oracle.rs and memory note `project_n657_mce2_is_noekeon.md`. We flash
# the host bin in plaintext at 0x70080000; enclave header lands at
# 0x70090000 (HOST_FLASH_BASE + 0x10000). MCE2 stays in passthrough.
# `tools/encrypt_mce2_n657.py` and `tools/mce2_brute_search.py` are
# kept as artifacts for a possible future Noekeon-based revival.

# Step 1: Convert ELF to raw binary
echo "[1/8] Converting ELF to binary..."
"$OBJCOPY" -O binary "$BOOT_ELF" "$BOOT_BIN"
echo "      ${BOOT_BIN} ($(wc -c < "$BOOT_BIN" | tr -d ' ') bytes)"

# Step 2: Add FSBL header (unsigned, dev mode)
# -la 0x34180000  : Load address — Boot ROM copies signed image here (AXISRAM2 base)
# -ep 0x34180641  : Entry point — first Thumb instruction (vector table reset addr +1)
# -of 0x80000000  : Option flags
# -align          : 0x400 byte alignment for payload
echo "[2/8] Adding FSBL header (unsigned, hv 2.3)..."
"$SIGNING_TOOL" \
    -bin "$BOOT_BIN" \
    -nk \
    -la 0x34180000 \
    -of 0x80000000 \
    -t fsbl \
    -hv 2.3 \
    -o "$FSBL_TRUSTED" \
    -dump "$FSBL_TRUSTED" \
    -align
echo "      ${FSBL_TRUSTED} ($(wc -c < "$FSBL_TRUSTED" | tr -d ' ') bytes)"

# Step 3: Clear TAMP_BKP[0] so FSBL re-runs the encryption oracle.
# Phase E.4c: 'UMBR' magic stays in BKP[0] across boots when VBAT
# external is alive. Every reflash needs to force the oracle to
# re-encrypt the new plaintext, otherwise stale ciphertext breaks
# HMAC validation downstream.
echo "[3/8] Clearing TAMP_BKP[0] (forces oracle re-run on next boot)..."
"$PROGRAMMER" \
    -c port=SWD mode=HOTPLUG ap=1 \
    -w32 0x56004100 0x00000000 \
    -hardRst

# Step 4: Erase XSPI2 (required — NOR flash won't update without erase)
# Erase 1MB to cover both FSBL (0x70000000) and host (0x70080000) regions.
echo "[4/8] Erasing XSPI2 (1MB to cover FSBL + host areas)..."
echo "      Make sure JP2 (BOOT1) is in position 2-3 (Dev Boot)!"
dd if=/dev/zero of=/tmp/_n657_erase.bin bs=4096 count=256 2>/dev/null
"$PROGRAMMER" \
    -c port=SWD mode=HOTPLUG ap=1 \
    -el "$EXT_LOADER" \
    -w /tmp/_n657_erase.bin 0x70000000 \
    -hardRst

# Step 5: Flash FSBL to XSPI2 at 0x70000000
echo "[5/8] Flashing FSBL to XSPI2 (0x70000000)..."
"$PROGRAMMER" \
    -c port=SWD mode=HOTPLUG ap=1 \
    -el "$EXT_LOADER" \
    -hardRst \
    -w "$FSBL_TRUSTED" 0x70000000

# Step 6: Flash host (NS bare-metal) to XSPI2 at 0x70080000.
# Path B-lite: the bin embeds the enclave (header + protect_enclave.py
# encrypted code) starting at offset 0x10000, so the enclave header
# lands at flash address 0x70090000. FSBL reads it from there directly
# (no MCE2 decrypt window required).
# Host selector — uses HOST_NAME / HOST_DIR exported by settings.sh.
# Falls back to bare_metal_n657 if settings.sh wasn't sourced. Override
# either via `source ./settings.sh` after `export HOST_APP=freertos`,
# or by directly setting HOST_NAME inline:
#   HOST_NAME=freertos_n657 ./tools/flash_n657.sh
HOST_NAME="${HOST_NAME:-bare_metal_n657}"
HOST_BIN="${ROOT_DIR}/host/${HOST_NAME}/bin/${HOST_NAME}.bin"
if [ -f "$HOST_BIN" ]; then
    echo "[6/8] Flashing host '${HOST_NAME}' to XSPI2 (0x70080000) — $(wc -c < "$HOST_BIN" | tr -d ' ') bytes..."
    "$PROGRAMMER" \
        -c port=SWD mode=HOTPLUG ap=1 \
        -el "$EXT_LOADER" \
        -hardRst \
        -w "$HOST_BIN" 0x70080000
else
    echo "[6/8] ERROR: host binary not found at $HOST_BIN"
    echo "      Build host first: cd host/${HOST_NAME} && make"
    exit 1
fi

# Step 7a (G.2.b): for object_detection_n657, flash NPU bytecode at
# 0x70200000. The FSBL boot-measures this region against the HMAC stamped
# in src/.../boot_measurements.rs (regenerated by rebuild_all.sh).
if [ "$HOST_NAME" = "object_detection_n657" ]; then
    BYTECODE_BIN="${ROOT_DIR}/host/object_detection_n657/build/model_bytecode.bin"
    if [ -f "$BYTECODE_BIN" ]; then
        echo "[7/8] Flashing NPU bytecode to XSPI2 (0x70200000) — $(wc -c < "$BYTECODE_BIN" | tr -d ' ') bytes..."
        "$PROGRAMMER" \
            -c port=SWD mode=HOTPLUG ap=1 \
            -el "$EXT_LOADER" \
            -hardRst \
            -w "$BYTECODE_BIN" 0x70200000
    else
        echo "[7/8] ERROR: bytecode not found at $BYTECODE_BIN"
        echo "       Run ./rebuild_all.sh first (HOST_APP=object_detection_n657)."
        exit 1
    fi

    # Step 7b (G.1.b.2.e): NPU weights blob. The FSBL also boot-measures
    # this region against MODEL_WEIGHTS_HMAC.
    MODEL_BIN="${ROOT_DIR}/host/object_detection_n657/Model/NUCLEO-N657X0-Q/network_data.xSPI2.bin"
    if [ -f "$MODEL_BIN" ]; then
        echo "[8/8] Flashing NN weights to XSPI2 (0x70380000) — $(wc -c < "$MODEL_BIN" | tr -d ' ') bytes..."
        "$PROGRAMMER" \
            -c port=SWD mode=HOTPLUG ap=1 \
            -el "$EXT_LOADER" \
            -hardRst \
            -w "$MODEL_BIN" 0x70380000
    else
        echo "[8/8] ERROR: NN weights blob not found at $MODEL_BIN"
        echo "       FSBL will halt with 'model weights HMAC mismatch'."
        exit 1
    fi
fi

echo ""
echo "=== Flash complete ==="
echo ""
echo "Next steps:"
echo "  1. Set JP2 (BOOT1) to position 1-2 (Flash Boot)"
echo "  2. Press RESET button"
echo "  3. Check UART at 115200 baud"
echo ""
