#!/bin/zsh
# Fault-injection harness
#
# Flow (STM32L5 with TZEN=1 can't write flash at runtime via openocd, so we
# corrupt the ELF at build time and re-flash via GDB):
#
#   1. rebuild_all.sh  -> clean compiled ELF
#   2. corrupt_enclave.py flips one ciphertext byte in ._enclave_code, leaving
#      the header's chained-measurement hmac untouched (header was computed
#      from the CLEAN ciphertext, so the kernel will chain a different value
#      and reject).
#   3. GDB batch-loads the tampered host ELF into flash via the running
#      openocd (assumes `make openocd` is already serving telnet:4444/gdb:3333).
#   4. picocom captures UART while we issue `reset run` via telnet.
#   5. Assert the rejection marker appears and the enclave did NOT run.
#
# Meaningful only once Task 2.5 has wired the `chained-measurement FAIL`
# marker.
#
# Historical note: openocd `flash fillw` is broken under STM32L5 TZEN=1
# (double-faults the target), which is why we patch the ELF and reflash via
# GDB rather than poking flash at runtime.

set -uo pipefail

UART="${UMBRA_UART:?Set UMBRA_UART to the target's serial device}"
OOCD_HOST="${UMBRA_OOCD_HOST:-localhost}"
OOCD_TELNET_PORT="${UMBRA_OOCD_TELNET_PORT:-4444}"
OOCD_GDB_PORT="${UMBRA_OOCD_GDB_PORT:-3333}"
LOG="tools/last_uart_fault.log"
WAIT_MS="${UMBRA_SMOKE_WAIT_MS:-10000}"

HOST_ELF="host/bare_metal_arm/bin/bare_metal_arm.elf"
BOOT_ELF="src/hardware/platform/stm32l552/boot/target/thumbv8m.main-none-eabi/release/boot"

# Corruption target: first ciphertext byte of block 0.
# With ess_miss_recovery, layout is [HMAC(32)|Meta(32)|CT(256)], so CT starts at 64.
# Without ess_miss_recovery, layout is [Meta(32)|CT(256)], so CT starts at 32.
CORRUPT_OFFSET="${UMBRA_CORRUPT_OFFSET:-64}"
EXPECT_MARKER="${UMBRA_EXPECT_MARKER:-[UMBRASecureBoot] chained-measurement FAIL}"

oocd_telnet() {
    nc -w 5 "$OOCD_HOST" "$OOCD_TELNET_PORT"
}

flash_elf() {
    # Non-interactive GDB load. Loads only program sections, exits cleanly.
    arm-none-eabi-gdb "$1" \
        -ex "target extended-remote :${OOCD_GDB_PORT}" \
        -ex 'set confirm off' \
        -ex "load $1" \
        -ex 'detach' \
        -ex 'quit' >/dev/null 2>&1
}

# 1. Rebuild a clean image.
echo "[fault] rebuilding clean image..."
./rebuild_all.sh >/dev/null 2>&1 || {
    echo "ERROR: rebuild_all.sh failed" >&2
    exit 2
}

# 2. Corrupt the host ELF in-place.
echo "[fault] corrupting ._enclave_code[${CORRUPT_OFFSET}]..."
python3 tools/corrupt_enclave.py "$HOST_ELF" "$CORRUPT_OFFSET" || {
    echo "ERROR: corrupt_enclave.py failed" >&2
    exit 2
}

# 3. Re-flash the boot ELF (unchanged) and the tampered host ELF.
echo "[fault] re-flashing boot ELF..."
flash_elf "$BOOT_ELF" || {
    echo "ERROR: gdb flash (boot) failed" >&2
    exit 2
}
echo "[fault] re-flashing tampered host ELF..."
flash_elf "$HOST_ELF" || {
    echo "ERROR: gdb flash (host) failed" >&2
    exit 2
}

# 4. Start UART capture BEFORE reset so we don't miss the banner.
pkill -f "picocom.*$UART" 2>/dev/null
sleep 0.3
: > "$LOG"
picocom -b 9600 -q --imap lfcrlf --logfile "$LOG" \
        --exit-after "$WAIT_MS" "$UART" >/dev/null 2>&1 &
PICO_PID=$!
sleep 1

printf 'reset run\nexit\n' | oocd_telnet >/dev/null 2>&1 || {
    echo "ERROR: could not reach openocd telnet on ${OOCD_HOST}:${OOCD_TELNET_PORT}" >&2
    kill "$PICO_PID" 2>/dev/null
    exit 2
}

wait "$PICO_PID" 2>/dev/null || true

# 5. Assert the rejection marker AND that the enclave did not run.
if grep -qF "$EXPECT_MARKER" "$LOG"; then
    if grep -qF "[USER] Enclave terminated" "$LOG"; then
        echo "FAULT INJECTION: FAIL -- enclave ran despite tampering"
        exit 1
    fi
    echo "FAULT INJECTION: PASS (enclave rejected as expected)"
    exit 0
else
    echo "FAULT INJECTION: FAIL -- rejection marker not found"
    echo "--- UART log tail (${LOG}) ---"
    tail -40 "$LOG"
    exit 1
fi
