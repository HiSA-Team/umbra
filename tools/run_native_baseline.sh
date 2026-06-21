#!/bin/bash
#
# Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
#
# Loops over the 13 TACLeBench mains used by the Umbra Stage A sweep
# and, for each, rebuilds the native_bench Tock TBF with that bench's
# Cargo feature, flashes the Tock image (NO Umbra enclave), captures
# UART until [BASELINE_END], parses the single [BASELINE_RUNTIME] row,
# and appends to `${BASELINE_CSV}` (default: ./baseline_master.csv).
#
# Per-bench TBFs keep each binary tiny (well under the 32 KB APPS_NS
# region), avoid `main` symbol collisions, and let one bench fault
# without affecting the others' measurements.
#
# Skip individual benches via `BASELINE_SKIP="anagram cjpeg_wrbmp"`.
# Run a single bench via `BASELINE_ONLY=ndes`.
#
# Output:
#   ./baseline_master.csv         ← header + 13 rows (idempotent on app)
#   ./eval_logs/native_<app>_*.log

set -eo pipefail
set +m
export LC_ALL=C

INVOCATION_DIR=${PWD}
SWEEP_DIR=${SWEEP_DIR:-${INVOCATION_DIR}/eval_logs}
mkdir -p "${SWEEP_DIR}"
BASELINE_CSV=${BASELINE_CSV:-${INVOCATION_DIR}/baseline_master.csv}

BASELINE_HEADER="app,native_cycles,native_result_r0"
[ -s "${BASELINE_CSV}" ] || echo "${BASELINE_HEADER}" > "${BASELINE_CSV}"

cd "$(dirname "$0")/.."
ROOT_DIR=$(pwd)

ALL_BENCHES=(fib bsort countnegative crc md5 insertsort
             ndes statemate petrinet adpcm_dec
             anagram cjpeg_wrbmp dijkstra)

# Apply BASELINE_ONLY / BASELINE_SKIP filters.
if [ -n "${BASELINE_ONLY}" ]; then
    BENCHES=(${BASELINE_ONLY})
else
    BENCHES=("${ALL_BENCHES[@]}")
fi
if [ -n "${BASELINE_SKIP}" ]; then
    FILTERED=()
    for b in "${BENCHES[@]}"; do
        skip=0
        for s in ${BASELINE_SKIP}; do
            if [ "$b" = "$s" ]; then skip=1; break; fi
        done
        [ "$skip" -eq 0 ] && FILTERED+=("$b")
    done
    BENCHES=("${FILTERED[@]}")
fi

echo "==> Running ${#BENCHES[@]} bench(es): ${BENCHES[*]}"
echo "==> Output: ${BASELINE_CSV}"

# Source settings.sh once (FLASHER, OPENOCD, GDB env).
source ./settings.sh >/dev/null 2>&1 || true
[ "${MCU_VARIANT}" = "stm32l552" ] || {
    echo "  FAIL — MCU_VARIANT must be stm32l552 (got '${MCU_VARIANT}')"
    exit 1
}

BOOT_ELF="${ROOT_DIR}/target/${TARGET_ARCH}/release/${BOOT_CRATE_NAME}"
NATIVE_ELF="${ROOT_DIR}/host/stm32l552/tock/bin/tock_native.elf"
[ -f "${BOOT_ELF}" ] || { echo "  FAIL — boot ELF missing: ${BOOT_ELF}"; exit 1; }

PASS=0
FAIL=0
FAILED_BENCHES=()

for BENCH in "${BENCHES[@]}"; do
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  BASELINE  ${BENCH}"
    echo "════════════════════════════════════════════════════════════════"

    UART_LOG="${SWEEP_DIR}/uart_native_${BENCH}.log"
    BUILD_LOG="${SWEEP_DIR}/build_native_${BENCH}.log"
    OOCD_LOG="${SWEEP_DIR}/openocd_native_${BENCH}.log"
    GDB_LOG="${SWEEP_DIR}/gdb_native_${BENCH}.log"

    # ── Build native_bench TBF with this single bench feature ──────────
    echo "  -- build (NATIVE_BENCH=bench_${BENCH})"
    if ! make -C host/stm32l552/tock NATIVE_BENCH=bench_${BENCH} image-native \
         >"${BUILD_LOG}" 2>&1; then
        echo "  FAIL — make image-native (last 30 lines):"
        tail -30 "${BUILD_LOG}"
        FAIL=$((FAIL + 1))
        FAILED_BENCHES+=("${BENCH}:BUILD")
        continue
    fi
    echo "  -- build OK ($(wc -l <"${BUILD_LOG}") lines logged)"

    # ── Openocd + UART capture ────────────────────────────────────────
    cleanup_inner() {
        [ -n "${CAT_PID}"  ] && { kill "${CAT_PID}"  2>/dev/null || true; wait "${CAT_PID}"  2>/dev/null || true; }
        [ -n "${OOCD_PID}" ] && {
            kill "${OOCD_PID}" 2>/dev/null || true
            sleep 0.3
            kill -0 "${OOCD_PID}" 2>/dev/null && kill -9 "${OOCD_PID}" 2>/dev/null || true
            wait "${OOCD_PID}" 2>/dev/null || true
        }
        pkill -9 -x openocd 2>/dev/null || true
        pkill -9 -f "/dev/cu.usbmodem" 2>/dev/null || true
    }

    CAT_PID=""
    OOCD_PID=""

    pkill -x openocd 2>/dev/null || true
    pkill -f "/dev/cu.usbmodem" 2>/dev/null || true
    sleep 1

    echo "  -- start OpenOCD"
    "${OPENOCD}" -f "${OPENOCD_CONFIG}" >"${OOCD_LOG}" 2>&1 &
    OOCD_PID=$!
    sleep 2

    UART=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
    [ -n "${UART}" ] || {
        echo "  FAIL — no /dev/cu.usbmodem*"
        cleanup_inner
        FAIL=$((FAIL + 1))
        FAILED_BENCHES+=("${BENCH}:NO_UART")
        continue
    }
    stty -f "${UART}" 9600 cs8 -parenb -cstopb raw -echo -echoe -echok 2>/dev/null || true
    : >"${UART_LOG}"
    ( cat "${UART}" >>"${UART_LOG}" 2>/dev/null ) &
    CAT_PID=$!
    sleep 0.5

    echo "  -- flash boot + tock_native(${BENCH}) + reset run"
    eval "${GDB} -batch -nx \
        -ex 'set confirm off' \
        -ex 'set pagination off' \
        -ex 'file ${BOOT_ELF}' \
        -ex 'target extended-remote :3333' \
        -ex 'monitor reset halt' \
        -ex 'monitor flash erase_address 0x08079000 0x7000' \
        -ex 'load' \
        -ex 'monitor reset halt' \
        -ex 'file ${NATIVE_ELF}' \
        -ex 'load' \
        -ex 'monitor reset run' \
        -ex 'detach' \
        -ex 'quit' \
        >\"${GDB_LOG}\" 2>&1" || {
        echo "  FAIL — GDB"
        tail -30 "${GDB_LOG}"
        cleanup_inner
        FAIL=$((FAIL + 1))
        FAILED_BENCHES+=("${BENCH}:GDB")
        continue
    }

    # ── Capture until [BASELINE_END] or timeout ──────────────────────
    CAPTURE_SECONDS=${CAPTURE_SECONDS:-180}
    DEADLINE=$(( $(date +%s) + CAPTURE_SECONDS ))
    MARKER_SEEN=false
    echo "  -- capture UART up to ${CAPTURE_SECONDS}s"
    while [ $(date +%s) -lt ${DEADLINE} ]; do
        if grep -q '\[BASELINE_END\]' "${UART_LOG}" 2>/dev/null; then
            MARKER_SEEN=true
            break
        fi
        sleep 1
    done

    cleanup_inner
    CAT_PID=""
    OOCD_PID=""

    if [ "${MARKER_SEEN}" = "false" ]; then
        echo "  FAIL — [BASELINE_END] not seen within ${CAPTURE_SECONDS}s. Last 20 UART lines:"
        tail -20 "${UART_LOG}"
        FAIL=$((FAIL + 1))
        FAILED_BENCHES+=("${BENCH}:TIMEOUT")
        continue
    fi

    # ── Parse the [BASELINE_RUNTIME] row ─────────────────────────────
    ROW=$(grep -E '^\[BASELINE_RUNTIME\]' "${UART_LOG}" | head -1)
    if [ -z "${ROW}" ]; then
        echo "  FAIL — no [BASELINE_RUNTIME] line in UART log"
        FAIL=$((FAIL + 1))
        FAILED_BENCHES+=("${BENCH}:NO_ROW")
        continue
    fi
    APP=$(printf '%s' "${ROW}" | sed -n 's/.*app=\([^[:space:]]*\).*/\1/p')
    CYCLES=$(printf '%s' "${ROW}" | sed -n 's/.*cycles=0x\([0-9A-Fa-f]*\).*/\1/p')
    RESULT=$(printf '%s' "${ROW}" | sed -n 's/.*result=0x\([0-9A-Fa-f]*\).*/\1/p')
    CYCLES_DEC=$(printf '%d' "0x${CYCLES}")

    # Idempotent insert.
    if grep -q "^${APP}," "${BASELINE_CSV}" 2>/dev/null; then
        TMPF=$(mktemp)
        grep -v "^${APP}," "${BASELINE_CSV}" > "${TMPF}"
        mv "${TMPF}" "${BASELINE_CSV}"
    fi
    echo "${APP},${CYCLES_DEC},0x${RESULT}" >> "${BASELINE_CSV}"
    echo "  PASS — ${APP} cycles=${CYCLES_DEC} (0x${CYCLES}) result=0x${RESULT}"
    PASS=$((PASS + 1))
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Summary:  PASS=${PASS}  FAIL=${FAIL}"
[ "${FAIL}" -gt 0 ] && echo "  Failed: ${FAILED_BENCHES[*]}"
echo "════════════════════════════════════════════════════════════════"
echo ""
column -s, -t < "${BASELINE_CSV}"
