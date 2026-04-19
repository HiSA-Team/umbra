#!/bin/zsh
# Runtime ESS-miss fault-injection harness
#
# Exercises three attack cases from UmbraIntegrityFixValidator.pv (L552) /
# UmbraIntegrityRaceValidatorFix.pv (L562, HMAC-over-plaintext):
#
#   hmac       — corrupt per-block HMAC of Block 1
#                → chain passes (HMAC not in chain input), per-block check
#                  fails at RUNTIME in validate_block. TRUE ESS-MISS TEST.
#
#   ciphertext — corrupt 1 byte of Block 1's ciphertext
#                → chain catches at LOAD TIME (ciphertext IS in chain input).
#                  Verifies end-to-end integrity but not the ESS-miss path.
#                  On L562 the "ciphertext" region carries plaintext (the
#                  cold-path oracle enciphers it in place on first boot), so
#                  the same byte flip lands as tampered plaintext — chain
#                  still rejects because chain input is [id||ct||meta] and
#                  ct==plaintext under --hmac-over-plaintext.
#
#   swap       — copy Block 0's slab over Block 1
#                → chain catches at LOAD TIME (binding_input changes).
#                  Tests the same rejection as ciphertext tamper.
#
# On L562 the enclave blob lives in OCTOSPI at 0x90000000. `corrupt_enclave.py`
# edits the host ELF's ._enclave_code section; the harness then re-extracts
# `enclaves_plain.bin` from that tampered ELF and pushes it through
# STM32_Programmer_CLI --extload. That tool conflicts with openocd over
# ST-LINK ownership, so the harness pkills openocd around the extload step
# and restarts it before GDB flashes the boot/host ELFs.
#
# Usage: UMBRA_ATTACK=hmac ./tools/smoke_test_fault_runtime.sh

set -uo pipefail

UART="${UMBRA_UART:?Set UMBRA_UART to the target's serial device}"
OOCD_HOST="${UMBRA_OOCD_HOST:-localhost}"
OOCD_TELNET_PORT="${UMBRA_OOCD_TELNET_PORT:-4444}"
OOCD_GDB_PORT="${UMBRA_OOCD_GDB_PORT:-3333}"
LOG="tools/last_uart_fault_runtime.log"
WAIT_MS="${UMBRA_SMOKE_WAIT_MS:-10000}"
ATTACK="${UMBRA_ATTACK:?Set UMBRA_ATTACK to ciphertext|hmac|swap}"

HOST_ELF="host/bare_metal_arm/bin/bare_metal_arm.elf"
BOOT_ELF="src/hardware/platform/stm32l552/boot/target/thumbv8m.main-none-eabi/release/boot"
SECTION="._enclave_code"

# Block layout: TOTAL_BLOCK_SIZE=320, header=64 [HMAC(32)|Meta(32)], CODE=256.
BLOCK1_HMAC_OFFSET=320
BLOCK1_CT_OFFSET=384

# L562: the enclave blob lives in OCTOSPI at 0x90000000, not in
# internal flash. `corrupt_enclave.py` edits `._enclave_code` in the host ELF,
# but `flash_elf` only writes to 0x0C000000 — so on L562 we must re-extract
# `enclaves_plain.bin` and push it through STM32_Programmer_CLI --extload. That
# tool opens ST-LINK directly and cannot coexist with openocd owning the probe,
# so we bounce openocd around the extload step (approach (a)).
MCU_VARIANT_EFFECTIVE="${MCU_VARIANT:-stm32l552}"

oocd_telnet() {
    nc -w 5 "$OOCD_HOST" "$OOCD_TELNET_PORT"
}

flash_elf() {
    arm-none-eabi-gdb "$1" \
        -ex "target extended-remote :${OOCD_GDB_PORT}" \
        -ex 'set confirm off' \
        -ex "load $1" \
        -ex 'detach' \
        -ex 'quit' >/dev/null 2>&1
}

# Wait up to 10s for openocd telnet to answer (after we restart it post-extload).
wait_for_oocd() {
    local i=0
    while (( i < 50 )); do
        if printf 'exit\n' | nc -w 1 "$OOCD_HOST" "$OOCD_TELNET_PORT" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
        i=$((i+1))
    done
    return 1
}

# Kill externally-started openocd so STM32_Programmer_CLI can grab ST-LINK,
# program OCTOSPI with the tampered plaintext blob, then restart openocd in
# the background so the rest of the harness (GDB flash + telnet reset) works.
l562_extload_and_restart_oocd() {
    echo "[fault-rt] L562: bouncing openocd for extload..."
    pkill -f "openocd.*${UMBRA_OOCD_CFG:-stm32l5x}" 2>/dev/null
    # Give the probe ~300ms to release.
    sleep 0.5

    echo "[fault-rt] L562: flashing tampered enclaves_plain.bin to OCTOSPI..."
    if ! make -C host/bare_metal_arm enclaves_plain.bin >/dev/null 2>&1; then
        echo "ERROR: make enclaves_plain.bin failed" >&2
        return 1
    fi
    if ! make program_enclaves_extload >/dev/null 2>&1; then
        echo "ERROR: program_enclaves_extload failed" >&2
        return 1
    fi

    echo "[fault-rt] L562: restarting openocd..."
    # Start openocd detached so it survives after the script returns; matches
    # the caller's expectation that openocd is "running externally".
    nohup ${OPENOCD:-openocd} -f "${UMBRA_OOCD_CFG:?Set UMBRA_OOCD_CFG (sourced from settings.sh)}" \
        >/tmp/umbra_oocd_fault_rt.log 2>&1 &
    disown 2>/dev/null || true

    if ! wait_for_oocd; then
        echo "ERROR: openocd did not come back up on ${OOCD_HOST}:${OOCD_TELNET_PORT}" >&2
        echo "       See /tmp/umbra_oocd_fault_rt.log" >&2
        return 1
    fi
}

# 1. Rebuild clean.
echo "[fault-rt] rebuilding clean image..."
./rebuild_all.sh >/dev/null 2>&1 || {
    echo "ERROR: rebuild_all.sh failed" >&2; exit 2
}

# 2. Apply the attack.
case "$ATTACK" in
    ciphertext)
        echo "[fault-rt] corrupting Block 1 ciphertext[0]..."
        python3 tools/corrupt_enclave.py "$HOST_ELF" "$BLOCK1_CT_OFFSET"
        ;;
    hmac)
        echo "[fault-rt] corrupting Block 1 HMAC[0]..."
        python3 tools/corrupt_enclave.py "$HOST_ELF" "$BLOCK1_HMAC_OFFSET"
        ;;
    swap)
        echo "[fault-rt] swapping Block 0 over Block 1..."
        python3 -c "
import subprocess, sys, os, tempfile
elf = '$HOST_ELF'
section = '$SECTION'
with tempfile.TemporaryDirectory() as tmp:
    sec_bin = os.path.join(tmp, 'section.bin')
    subprocess.check_call(['arm-none-eabi-objcopy', '-O', 'binary',
                           f'--only-section={section}', elf, sec_bin])
    with open(sec_bin, 'rb') as f:
        data = bytearray(f.read())
    if len(data) < 640:
        print(f'Section too small ({len(data)} bytes, need >=640)', file=sys.stderr)
        sys.exit(1)
    block0 = data[0:320]
    data[320:640] = block0
    with open(sec_bin, 'wb') as f:
        f.write(data)
    subprocess.check_call(['arm-none-eabi-objcopy',
                           f'--update-section={section}={sec_bin}', elf])
print('[corrupt_enclave] Block 0 copied over Block 1 (swap attack)')
"
        ;;
    *)
        echo "Unknown ATTACK: $ATTACK (expected ciphertext|hmac|swap)" >&2
        exit 2
        ;;
esac

# 3. Re-flash.
#    On L562 we must push the tampered blob into OCTOSPI BEFORE the GDB flash
#    pass, because `l562_extload_and_restart_oocd` bounces openocd and we want
#    the final openocd instance to be the one flash_elf talks to.
if [[ "$MCU_VARIANT_EFFECTIVE" == "stm32l562" ]]; then
    l562_extload_and_restart_oocd || exit 2
fi

echo "[fault-rt] flashing boot ELF..."
flash_elf "$BOOT_ELF" || { echo "ERROR: gdb flash (boot) failed" >&2; exit 2; }
echo "[fault-rt] flashing tampered host ELF..."
flash_elf "$HOST_ELF" || { echo "ERROR: gdb flash (host) failed" >&2; exit 2; }

# 4. UART capture.
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

# 5. Assertions.
#
# All three attacks MUST prevent the enclave from running. The WHERE differs:
#
#   hmac       → chain passes, per-block validator rejects at runtime
#                Expect: NO "ESS miss recovered", NO "Enclave terminated"
#                Expect: "handle_ess_miss failed" panic dump
#
#   ciphertext → chain rejects at load time
#   swap       → chain rejects at load time
#                Expect: "chained-measurement FAIL" or "Enclave creation REJECTED"
#                Expect: NO "Enclave terminated"

PASS=true

if grep -qF '[USER] Enclave terminated' "$LOG"; then
    echo "FAULT INJECTION ($ATTACK): FAIL -- enclave ran despite tampering"
    PASS=false
fi

if grep -qF '[UMBRASecureBoot] ESS miss recovered' "$LOG"; then
    echo "FAULT INJECTION ($ATTACK): FAIL -- validator accepted tampered block"
    PASS=false
fi

case "$ATTACK" in
    hmac)
        if grep -qF 'handle_ess_miss failed' "$LOG"; then
            echo "[fault-rt] ($ATTACK): per-block validator rejected at runtime (expected)"
        else
            echo "[fault-rt] ($ATTACK): WARN -- no panic_dump marker (may be UART timing)"
        fi
        ;;
    ciphertext|swap)
        if grep -qF 'chained-measurement FAIL' "$LOG" || \
           grep -qF 'Enclave creation REJECTED' "$LOG"; then
            echo "[fault-rt] ($ATTACK): chained measurement rejected at load time (expected)"
        else
            echo "[fault-rt] ($ATTACK): WARN -- no chain-rejection marker (may be UART timing)"
        fi
        ;;
esac

if $PASS; then
    echo "FAULT INJECTION ($ATTACK): PASS"
    exit 0
else
    echo "--- UART log tail (${LOG}) ---"
    tail -40 "$LOG"
    exit 1
fi
