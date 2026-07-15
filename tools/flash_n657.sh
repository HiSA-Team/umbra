#!/bin/bash
#
# Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
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

# Source settings.sh so BOOT_CRATE_NAME / HOST_APP / HOST_DIR derive from
# MCU_VARIANT cleanly — without this, any leftover BOOT_CRATE_NAME from a
# previous `source ./settings.sh` for an L5xx target would win and we'd
# try to flash umbra-l552-boot-trusted.bin against N657's XSPI2. xtask
# sets MCU_VARIANT=stm32n657 in this script's env, so re-deriving via
# settings.sh is correct + idempotent. debug.sh does the same on line 4.
# shellcheck disable=SC1091
. "${ROOT_DIR}/settings.sh" >/dev/null 2>&1

# N657 boot crate is `umbra-n657-boot`; the build artifact lives under
# the workspace target/ at ROOT_DIR. BOOT_CRATE_NAME comes from
# settings.sh on the host or falls back to the explicit name for
# standalone script runs.
BOOT_CRATE_NAME="${BOOT_CRATE_NAME:-umbra-n657-boot}"
BOOT_ELF="${ROOT_DIR}/target/thumbv8m.main-none-eabi/release/${BOOT_CRATE_NAME}"
BOOT_BIN="${ROOT_DIR}/target/thumbv8m.main-none-eabi/release/${BOOT_CRATE_NAME}.bin"
FSBL_TRUSTED="${ROOT_DIR}/target/thumbv8m.main-none-eabi/release/${BOOT_CRATE_NAME}-trusted.bin"

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
    echo "ERROR: Boot ELF not found at $BOOT_ELF"
    echo "       Run: MCU_VARIANT=stm32n657 ./rebuild_all.sh"
    echo "       (or: cargo xtask build n657)"
    exit 1
fi

echo "=== STM32N657 FSBL Flash Tool (plaintext flash) ==="
echo ""
# MCE2 encryption-at-rest is DEFERRED — see boot crate's oracle.rs and
# memory note `project_n657_mce2_is_noekeon.md`. We flash the host bin
# in plaintext at 0x70080000; enclave header lands at 0x70090000
# (HOST_FLASH_BASE + 0x10000). MCE2 stays in passthrough.
# `tools/encrypt_mce2_n657.py` and `tools/mce2_brute_search.py` are
# kept as artifacts for a possible future Noekeon-based revival.

# Convert ELF to raw binary
echo "[1/8] Converting ELF to binary..."
"$OBJCOPY" -O binary "$BOOT_ELF" "$BOOT_BIN"
echo "      ${BOOT_BIN} ($(wc -c < "$BOOT_BIN" | tr -d ' ') bytes)"

# Sign the FSBL (ECDSA-P256, authenticated v2.3 header, -of 0x80000001).
# Fresh throwaway keys per build; see tools/sign_fsbl_n657.sh. The Boot ROM
# does not enforce the signature on the BSEC-open board (that needs the OTP
# close), so a signed image boots identically — this is the FSBL signing pipeline.
echo "[2/8] Signing FSBL (ECDSA-P256 v2.3, fresh keys)..."
"${ROOT_DIR}/tools/sign_fsbl_n657.sh" "$BOOT_BIN" "$FSBL_TRUSTED"
echo "      ${FSBL_TRUSTED} ($(wc -c < "$FSBL_TRUSTED" | tr -d ' ') bytes)"

# Clear TAMP_BKP[0] so FSBL re-runs the encryption oracle.
# The 'UMBR' magic stays in BKP[0] across boots when VBAT external is
# alive. Every reflash needs to force the oracle to re-encrypt the new
# plaintext, otherwise stale ciphertext breaks HMAC validation
# downstream.
echo "[3/8] Clearing TAMP_BKP[0] (forces oracle re-run on next boot)..."
"$PROGRAMMER" \
    -c port=SWD mode=HOTPLUG ap=1 \
    -w32 0x56004100 0x00000000 \
    -hardRst

# Erase XSPI2 (required — NOR flash won't update without erase)
# Erase 1MB to cover both FSBL (0x70000000) and host (0x70080000) regions.
echo "[4/8] Erasing XSPI2 (1MB to cover FSBL + host areas)..."
echo "      Make sure JP2 (BOOT1) is in position 2-3 (Dev Boot)!"
dd if=/dev/zero of=/tmp/_n657_erase.bin bs=4096 count=256 2>/dev/null
"$PROGRAMMER" \
    -c port=SWD mode=HOTPLUG ap=1 \
    -el "$EXT_LOADER" \
    -w /tmp/_n657_erase.bin 0x70000000 \
    -hardRst

# Flash FSBL to XSPI2 at 0x70000000
echo "[5/8] Flashing FSBL to XSPI2 (0x70000000)..."
"$PROGRAMMER" \
    -c port=SWD mode=HOTPLUG ap=1 \
    -el "$EXT_LOADER" \
    -hardRst \
    -w "$FSBL_TRUSTED" 0x70000000

# Flash FSBL copy 2 to XSPI2 at 0x70040000 (UM3234 §3.5.3: ROM searches FSBL1
# @0x0 and FSBL2 @0x40000, falling back to FSBL2 if FSBL1 fails to load). Same
# signed image — the fail-safe second copy. Host @0x70080000 is unaffected
# (both FSBL slots fit [0x00000, 0x80000)).
echo "[5b/8] Flashing FSBL copy 2 to XSPI2 (0x70040000)..."
"$PROGRAMMER" \
    -c port=SWD mode=HOTPLUG ap=1 \
    -el "$EXT_LOADER" \
    -hardRst \
    -w "$FSBL_TRUSTED" 0x70040000

# Flash host (NS bare-metal) to XSPI2 at 0x70080000.
# Path B-lite: the bin embeds the enclave (header + protect_enclave.py
# encrypted code) starting at offset 0x10000, so the enclave header
# lands at flash address 0x70090000. FSBL reads it from there directly
# (no MCE2 decrypt window required).
# Host selector — uses HOST_APP / HOST_DIR exported by settings.sh.
# Falls back to bare_metal if settings.sh wasn't sourced. Override either
# via `source ./settings.sh` after `export HOST_APP=freertos`, or by
# directly setting HOST_APP inline:
#   HOST_APP=freertos ./tools/flash_n657.sh
HOST_APP="${HOST_APP:-bare_metal}"
HOST_BIN="${ROOT_DIR}/host/stm32n657/${HOST_APP}/bin/${HOST_APP}.bin"
if [ -f "$HOST_BIN" ]; then
    echo "[6/8] Flashing host '${HOST_APP}' to XSPI2 (0x70080000) — $(wc -c < "$HOST_BIN" | tr -d ' ') bytes..."
    "$PROGRAMMER" \
        -c port=SWD mode=HOTPLUG ap=1 \
        -el "$EXT_LOADER" \
        -hardRst \
        -w "$HOST_BIN" 0x70080000
else
    echo "[6/8] ERROR: host binary not found at $HOST_BIN"
    echo "      Build host first: cd host/stm32n657/${HOST_APP} && make"
    exit 1
fi

# for two_enclaves, flash the TWO standalone enclave blobs at distinct XSPI2
# offsets. Unlike bare_metal (which embeds one enclave inside the host bin),
# two_enclaves ships ammunition + ndes as SEPARATE protected .bin blobs; the
# host src/main.c passes these flash addresses to umbra_enclave_create() and
# runs both sequentially. Both offsets sit inside the 1 MB erased above
# (0x70000000..0x70100000) and clear of the host (~71 KB at 0x70080000) and
# the MCE2 region (0x70500000). The addresses MUST match the #defines in
# host/stm32n657/two_enclaves/src/main.c (AMMUNITION_FLASH_ADDR / NDES_FLASH_ADDR).
if [ "$HOST_APP" = "two_enclaves" ]; then
    AMMU_BLOB="${ROOT_DIR}/host/stm32n657/two_enclaves/app/ammunition.bin"
    NDES_BLOB="${ROOT_DIR}/host/stm32n657/two_enclaves/app/ndes.bin"
    for pair in "$AMMU_BLOB:0x700A0000" "$NDES_BLOB:0x700C0000"; do
        blob="${pair%%:*}"
        addr="${pair##*:}"
        if [ ! -f "$blob" ]; then
            echo "[6b/8] ERROR: enclave blob not found at $blob"
            echo "       Build it first: make -C host/stm32n657/two_enclaves"
            exit 1
        fi
        echo "[6b/8] Flashing enclave blob $(basename "$blob") to XSPI2 ($addr) — $(wc -c < "$blob" | tr -d ' ') bytes..."
        "$PROGRAMMER" \
            -c port=SWD mode=HOTPLUG ap=1 \
            -el "$EXT_LOADER" \
            -hardRst \
            -w "$blob" "$addr"
    done
fi

# Provision the A/B enclave-update slots (remote attestation + secure update,
# ADR 013). When UMBRA_ATTEST_SLOTS=1 and ENCLAVE_SLOT_BLOB points at a
# protect_enclave.py output blob, write it into SLOT_A (0x73D00000) so
# umbra_enclave_create(0) authenticates it and runs it. SLOT_B (0x73D80000) is
# filled later by a remote `umbra_enclave_update`. Both slots sit below the
# state-continuity region (0x73F00000) and outside the 1 MB FSBL/host erase, so
# provisioning them needs its own erase. Default flows leave this untouched.
if [ "${UMBRA_ATTEST_SLOTS:-0}" = "1" ]; then
    SLOT_BLOB="${ENCLAVE_SLOT_BLOB:-}"
    if [ -z "$SLOT_BLOB" ] || [ ! -f "$SLOT_BLOB" ]; then
        echo "[6c/8] ERROR: UMBRA_ATTEST_SLOTS=1 but ENCLAVE_SLOT_BLOB not set/found ($SLOT_BLOB)"
        echo "       Point it at a protect_enclave.py output blob (48-byte UMBR header + blocks)."
        exit 1
    fi
    # Invalidate SLOT_B so create(0) never selects stale data from a previous session.
    # STM32_Programmer_CLI `-e` takes SECTOR NUMBERS (not addresses); the rest of this
    # script erases via `-w` (a write auto-erases the 64 KB NOR sector it touches). So
    # write one 0xFF page to SLOT_B's base — the auto-erase clears the whole sector and
    # leaves the header at 0xFF (bad magic → not selectable). SLOT_A's blob write below
    # auto-erases SLOT_A the same way.
    SLOT_ERASE=/tmp/_n657_slot_erase.bin
    # 4 KB of 0xFF. (macOS `tr '\0' '\377'` mis-encodes to UTF-8 in a non-C locale, so
    # use perl for raw bytes.)
    perl -e 'print "\xff" x 4096' > "$SLOT_ERASE"
    echo "[6c/8] Invalidating enclave SLOT_B (0x73D80000)..."
    "$PROGRAMMER" \
        -c port=SWD mode=HOTPLUG ap=1 \
        -el "$EXT_LOADER" \
        -hardRst \
        -w "$SLOT_ERASE" 0x73D80000
    echo "[6c/8] Provisioning enclave SLOT_A (0x73D00000) — $(wc -c < "$SLOT_BLOB" | tr -d ' ') bytes..."
    "$PROGRAMMER" \
        -c port=SWD mode=HOTPLUG ap=1 \
        -el "$EXT_LOADER" \
        -hardRst \
        -w "$SLOT_BLOB" 0x73D00000
fi

# for object_detection, flash NPU bytecode at 0x70200000.
# The FSBL boot-measures this region against the HMAC stamped in
# src/.../boot_measurements.rs (regenerated by rebuild_all.sh).
if [ "$HOST_APP" = "object_detection" ]; then
    BYTECODE_BIN="${ROOT_DIR}/host/stm32n657/object_detection/build/model_bytecode.bin"
    if [ -f "$BYTECODE_BIN" ]; then
        echo "[7/8] Flashing NPU bytecode to XSPI2 (0x70200000) — $(wc -c < "$BYTECODE_BIN" | tr -d ' ') bytes..."
        "$PROGRAMMER" \
            -c port=SWD mode=HOTPLUG ap=1 \
            -el "$EXT_LOADER" \
            -hardRst \
            -w "$BYTECODE_BIN" 0x70200000
    else
        echo "[7/8] ERROR: bytecode not found at $BYTECODE_BIN"
        echo "       Run ./rebuild_all.sh first (HOST_APP=object_detection)."
        exit 1
    fi

    # NPU weights blob. The FSBL also boot-measures this region
    # against MODEL_WEIGHTS_HMAC.
    MODEL_BIN="${ROOT_DIR}/host/stm32n657/object_detection/Model/NUCLEO-N657X0-Q/network_data.xSPI2.bin"
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
