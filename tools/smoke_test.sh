#!/usr/bin/env bash
# T3 smoke-test harness.
# Prereqs: `make openocd` running in another shell (telnet port 4444 reachable).
#
# Flow:
#   1. Start picocom in the background (it auto-exits after WAIT_MS).
#   2. Wait briefly for picocom to open the port.
#   3. Issue `reset run` via openocd telnet so boot starts from a known state.
#   4. Wait for picocom to finish, then normalize + diff against the golden.
#
# Drift handling: the golden marks lines with a trailing `//ALLOW_DRIFT` tag.
# We normalize both files before diffing: the tag is stripped, and hex values
# on the tagged lines are replaced with a placeholder. This makes stack SP /
# size values tolerable while still catching structural regressions.

set -uo pipefail

UART="${UMBRA_UART:?Set UMBRA_UART to the target serial device}"
LOG="tools/last_uart.log"

# Shared helpers (LC_ALL fix, oocd_telnet, start_picocom_capture,
# target_reset_run, plus UMBRA_OOCD_HOST/PORT/WAIT_MS defaults).
source "$(cd "$(dirname "$0")" && pwd)/smoke_test_lib.sh"

# L552 and L562 produce different UART traces
# Pick the golden that matches the current build.
MCU_VARIANT_EFFECTIVE="${MCU_VARIANT:-stm32l552}"
if [[ "$MCU_VARIANT_EFFECTIVE" == "stm32l562" ]]; then
    GOLDEN="tools/golden_uart_l562.log"
else
    GOLDEN="tools/golden_uart.log"
fi

# Start picocom FIRST so we don't race the reset.
start_picocom_capture "$LOG"

# Reset the target via the already-running openocd daemon's telnet port.
if ! target_reset_run; then
    echo "ERROR: could not reach openocd telnet at $UMBRA_OOCD_HOST:$UMBRA_OOCD_TELNET_PORT." >&2
    echo "       Start it in another shell with: make openocd" >&2
    kill "$PICO_PID" 2>/dev/null
    exit 2
fi

# Wait for picocom to self-terminate via --exit-after.
wait "$PICO_PID" 2>/dev/null || true

if [[ ! -f "$GOLDEN" ]]; then
    echo "No golden at $GOLDEN -- bootstrapping from this run."
    cp "$LOG" "$GOLDEN"
    echo "Review $GOLDEN, commit it, and re-run smoke_test.sh."
    exit 0
fi

# Normalize: strip //ALLOW_DRIFT tag (documentation-only in the golden) and
# mask 0xHEX on lines whose content matches the drift-allowed patterns below.
# Add more patterns here if other lines prove volatile.
normalize() {
    tr -d '\200-\377' < "$1" \
    | sed -E -e '/_umb_stack_size:/s/0x[0-9A-Fa-f]+/0xDRIFT/g' -e '/Current Secure Stack Usage:/s/0x[0-9A-Fa-f]+/0xDRIFT/g' -e '/Remaining Secure Stack:/s/0x[0-9A-Fa-f]+/0xDRIFT/g' -e '/SHCSR before:/s/0x[0-9A-Fa-f]+/0xDRIFT/g' -e '/SHCSR after:/s/0x[0-9A-Fa-f]+/0xDRIFT/g' -e 's| //ALLOW_DRIFT$||' \
    | awk '/\[USER\] Enclave preempted/ { if (!seen_preempt) { print; seen_preempt=1 } next } { seen_preempt=0; print }' \
    | awk '{ lines[NR]=$0 } /[^ \t]/{last=NR} END{ for(i=1;i<=last;i++) print lines[i] }'
}

if diff <(normalize "$GOLDEN") <(normalize "$LOG") >/dev/null; then
    echo "SMOKE TEST: PASS"
    exit 0
else
    echo "SMOKE TEST: FAIL -- drift from golden UART output"
    diff <(normalize "$GOLDEN") <(normalize "$LOG") | head -60
    exit 1
fi
