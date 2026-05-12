# Shared helpers for tools/smoke_test*.sh. Source this AFTER the caller's
# `UART="${UMBRA_UART:?...}"` assertion line — the helpers read `$UART`
# directly along with the env-derived defaults below.
#
# Not executable on its own; intended to be `source`d.

# Force C locale so BSD sed under en_US.UTF-8 doesn't choke on raw bytes
# (L562's boot ROM emits 0xFE before main()).
export LC_ALL=C

: "${UMBRA_OOCD_HOST:=localhost}"
: "${UMBRA_OOCD_TELNET_PORT:=4444}"
: "${UMBRA_OOCD_GDB_PORT:=3333}"
: "${UMBRA_SMOKE_WAIT_MS:=10000}"

# Pipe a telnet command sequence to the already-running openocd daemon.
# Usage: printf 'reset run\nexit\n' | oocd_telnet
oocd_telnet() {
    nc -w 5 "$UMBRA_OOCD_HOST" "$UMBRA_OOCD_TELNET_PORT"
}

# Non-interactive GDB load of an ELF via openocd's GDB port.
# Usage: flash_elf path/to/foo.elf
flash_elf() {
    arm-none-eabi-gdb "$1" \
        -ex "target extended-remote :${UMBRA_OOCD_GDB_PORT}" \
        -ex 'set confirm off' \
        -ex "load $1" \
        -ex 'detach' \
        -ex 'quit' >/dev/null 2>&1
}

# Kill any stray picocom holding the UART, then start a fresh background
# picocom that auto-exits after UMBRA_SMOKE_WAIT_MS and logs to $1.
# Sets global PICO_PID; the caller `wait $PICO_PID` or `kill $PICO_PID`.
# Usage: start_picocom_capture path/to/uart.log
start_picocom_capture() {
    local log_path="$1"
    pkill -f "picocom.*$UART" 2>/dev/null
    sleep 0.3
    : > "$log_path"
    picocom -b 9600 -q --imap lfcrlf --logfile "$log_path" \
            --exit-after "$UMBRA_SMOKE_WAIT_MS" "$UART" >/dev/null 2>&1 &
    PICO_PID=$!
    sleep 1
}

# Send `reset run` to the target via openocd's telnet port. Returns non-zero
# (does NOT exit) if the daemon is unreachable; the caller decides whether
# to clean up its picocom child and bail.
# Usage: target_reset_run || { kill "$PICO_PID"; exit 2; }
target_reset_run() {
    printf 'reset run\nexit\n' | oocd_telnet >/dev/null 2>&1
}
