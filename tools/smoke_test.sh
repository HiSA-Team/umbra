#!/bin/zsh
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

# L562 boot ROM emits a raw 0xFE status byte on UART before main() runs.
# 0xFE is not a valid UTF-8 lead byte, so BSD sed under an en_US.UTF-8 locale
# errors with "RE error: illegal byte sequence" mid-pipeline and the
# normalize() call returns truncated output. Forcing C locale makes sed
# process input as raw bytes.
export LC_ALL=C

UART="${UMBRA_UART:?Set UMBRA_UART to the target's serial device}"
OOCD_HOST="${UMBRA_OOCD_HOST:-localhost}"
OOCD_TELNET_PORT="${UMBRA_OOCD_TELNET_PORT:-4444}"
LOG="tools/last_uart.log"
WAIT_MS="${UMBRA_SMOKE_WAIT_MS:-10000}"

# L552 and L562 produce different UART traces
# Pick the golden that matches the current build.
MCU_VARIANT_EFFECTIVE="${MCU_VARIANT:-stm32l552}"
if [[ "$MCU_VARIANT_EFFECTIVE" == "stm32l562" ]]; then
    GOLDEN="tools/golden_uart_l562.log"
else
    GOLDEN="tools/golden_uart.log"
fi

# Kill any stray picocom holding the port.
pkill -f "picocom.*$UART" 2>/dev/null
sleep 0.3

: > "$LOG"

# Start picocom FIRST so we don't race the reset.
picocom -b 9600 -q --imap lfcrlf --logfile "$LOG" \
        --exit-after "$WAIT_MS" "$UART" >/dev/null 2>&1 &
PICO_PID=$!

# Give picocom a moment to open the port.
sleep 1

# Reset the target via the already-running openocd daemon's telnet port.
if ! printf 'reset run\nexit\n' | nc -w 2 "$OOCD_HOST" "$OOCD_TELNET_PORT" >/dev/null 2>&1; then
    echo "ERROR: could not reach openocd telnet at $OOCD_HOST:$OOCD_TELNET_PORT." >&2
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
    sed -E '
        /_umb_stack_size:/           s/0x[0-9A-Fa-f]+/0xDRIFT/g
        /Current Secure Stack Usage:/ s/0x[0-9A-Fa-f]+/0xDRIFT/g
        /Remaining Secure Stack:/    s/0x[0-9A-Fa-f]+/0xDRIFT/g
        /SHCSR before:/              s/0x[0-9A-Fa-f]+/0xDRIFT/g
        /SHCSR after:/               s/0x[0-9A-Fa-f]+/0xDRIFT/g
        s| //ALLOW_DRIFT$||
    ' "$1" \
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
