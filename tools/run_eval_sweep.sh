#!/bin/bash
#
# Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
#
#
# Drives one (slot, cache, spec, app, rep) cell of the §Evaluation grid:
#   1. Builds the secure boot + Tock host with the knob env (`UMBRA_*`)
#      and `bench-eval`/`umbra-speculation` features wired through
#      settings.sh.
#   2. Flashes boot + tock host via OpenOCD+GDB batch.
#      For non-fib apps (Step 6+) ALSO flashes the bench .bin at the
#      Tock host's NS scan slot 0x08079000.
#   3. Captures UART, waits for "[TOCK] All enclaves done", and parses
#      the [EVAL_DUMP_BEGIN/END] block.
#   4. Appends an idempotent row to `${CSV_LOG}` keyed on
#      (slot, cache, spec, app, rep). Re-runs with the same args
#      return immediately if the row exists (R-A from grilling Q6c).
#   5. Failure mode F1: append row with pass_fail=FAIL and continue.
#
#
# Usage (env-driven):
#   SWEEP_APP=fib SWEEP_SLOT=256 SWEEP_CACHE=64 SWEEP_SPEC=1 SWEEP_REP=0 \
#     ./tools/run_eval_sweep.sh
#
# Defaults give a single sanity-check cell. Step 6's full grid wraps
# this script in a nested for-loop.

set -eo pipefail

# Disable bash job control so SIGTERM/SIGKILL on background openocd/cat
# don't print "Terminated: 15" notices to stderr — those are info-only
# but get mixed with PASS/FAIL output and look like errors.
set +m

# Force byte-locale processing for every text tool we invoke (awk, grep,
# sed, tr). The UART occasionally leaks a garbage byte at the start of
# the log (cat racing with the device opening), which makes BSD awk on
# macOS bail with "towc: multibyte conversion failure". LC_ALL=C bypasses
# multibyte handling and processes the log as raw bytes.
export LC_ALL=C

# ── Cell key ───────────────────────────────────────────────────────────
SWEEP_APP=${SWEEP_APP:-fib}
SWEEP_SLOT=${SWEEP_SLOT:-256}
SWEEP_CACHE=${SWEEP_CACHE:-64}
SWEEP_SPEC=${SWEEP_SPEC:-1}
SWEEP_REP=${SWEEP_REP:-0}

# ── Per-run logs + master CSV ──────────────────────────────────────────
# Output lives where the user invoked the script (NOT /tmp), so an
# iterative sweep survives reboots and is easy to git-ignore per repo.
# Override with `SWEEP_DIR=...` env var to redirect somewhere else.
# Captured at script entry, BEFORE the later `cd` to ROOT_DIR.
INVOCATION_DIR=${PWD}
SWEEP_DIR=${SWEEP_DIR:-${INVOCATION_DIR}/eval_logs}
mkdir -p "${SWEEP_DIR}"
CSV_LOG=${CSV_LOG:-${INVOCATION_DIR}/eval_master.csv}
CELL_TAG="${SWEEP_APP}_slot${SWEEP_SLOT}_cache${SWEEP_CACHE}_spec${SWEEP_SPEC}_rep${SWEEP_REP}"
UART_LOG="${SWEEP_DIR}/uart_${CELL_TAG}.log"
BUILD_LOG="${SWEEP_DIR}/build_${CELL_TAG}.log"
OOCD_LOG="${SWEEP_DIR}/openocd_${CELL_TAG}.log"
GDB_LOG="${SWEEP_DIR}/gdb_${CELL_TAG}.log"

# CSV schema (one row per cell, header injected once on first write):
CSV_HEADER="slot_bytes,cache_limit,speculation,app,rep_idx,host_mode,blob_size,boot_ns_cycles,boot_sec_cycles,runtime_cycles,switch_min_cycles,switch_mean_cycles,switch_max_cycles,switch_count,null_svc_cycles,pass_fail,uart_log_path,build_hash"

# Initialise CSV header if file is missing or empty.
if [ ! -s "${CSV_LOG}" ]; then
    echo "${CSV_HEADER}" > "${CSV_LOG}"
fi

# ── Idempotency check (R-A) ────────────────────────────────────────────
# If a row with this exact (slot, cache, spec, app, rep) tuple already
# exists, skip the rebuild + flash + run cycle. Re-running the script
# with `rm /tmp/umbra_sweep/eval_master.csv` forces a full re-do.
EXISTING_ROW=$(awk -F',' -v s="${SWEEP_SLOT}" -v c="${SWEEP_CACHE}" -v sp="${SWEEP_SPEC}" \
                    -v a="${SWEEP_APP}" -v r="${SWEEP_REP}" \
    'NR > 1 && $1==s && $2==c && $3==sp && $4==a && $5==r' "${CSV_LOG}" | head -1)
if [ -n "${EXISTING_ROW}" ]; then
    echo "==> SKIP cell ${CELL_TAG} — already in CSV:"
    echo "    ${EXISTING_ROW}"
    exit 0
fi

# ── Boot env (propagates to .cargo/config.toml + settings.sh) ──────────
#
# Special case for CACHE=0: the kernel doesn't support a literal 0
# (it would deadlock — see Step 0a grilling notes). We map CACHE=0 to
# the `cache-zero-mode` feature, which forces effective_limit=1 inside
# handle_ess_miss + skips BFS multi-load + skips force-load. The
# CACHE_LIMIT const stays at 64 in the build (irrelevant when cache-
# zero-mode is on; the runtime path ignores it).
export UMBRA_SLOT_SIZE_BYTES="${SWEEP_SLOT}"
if [ "${SWEEP_CACHE}" = "0" ]; then
    export UMBRA_CACHE_LIMIT=64
    export UMBRA_CACHE_ZERO_MODE=1
else
    export UMBRA_CACHE_LIMIT="${SWEEP_CACHE}"
    unset UMBRA_CACHE_ZERO_MODE
fi
export UMBRA_BENCH_EVAL=1
if [ "${SWEEP_SPEC}" = "0" ]; then
    export UMBRA_SPECULATION=0
else
    unset UMBRA_SPECULATION
fi

# Build hash so we can detect a stale flash if the rebuild silently
# cached. Sha1 of the knob tuple ≈ unique per (slot, cache, spec).
BUILD_HASH=$(printf "%s|%s|%s" "${SWEEP_SLOT}" "${SWEEP_CACHE}" "${SWEEP_SPEC}" \
             | shasum -a 1 | awk '{print substr($1, 1, 12)}')

echo "════════════════════════════════════════════════════════════════"
echo "  CELL ${CELL_TAG}  build=${BUILD_HASH}"
echo "════════════════════════════════════════════════════════════════"

# ── Run rebuild_all.sh (env-driven) ────────────────────────────────────
#
# SWEEP_SKIP_BUILD=1 short-circuits the rebuild — the grid wrapper
# (run_eval_grid.sh) sets it when iterating apps within the same
# (slot, cache, spec) config: one build is reused across all apps for
# that config, saving ~30s × N_apps × N_reps per kernel rebuild. With
# the full grid (~46 builds × 30s = 23 min vs 1518 × 30s = 12.6 h),
# this is the difference between "feasible overnight" and "infeasible".
cd "$(dirname "$0")/.."
ROOT_DIR=$(pwd)

if [ "${SWEEP_SKIP_BUILD:-0}" = "1" ]; then
    echo "  -- SKIP rebuild_all.sh (SWEEP_SKIP_BUILD=1; assumes kernel already built for this (slot,cache,spec))"
else
    echo "  -- rebuild_all.sh (UMBRA_SLOT_SIZE_BYTES=${SWEEP_SLOT}, UMBRA_CACHE_LIMIT=${SWEEP_CACHE}, UMBRA_SPECULATION=${SWEEP_SPEC}, UMBRA_CACHE_ZERO_MODE=${UMBRA_CACHE_ZERO_MODE:-0}, UMBRA_BENCH_EVAL=1)"
    # Force a Tock-host enclave_payload rebuild — staleness on
    # master_key.bin timestamps has bitten before (see Step 4 trace).
    rm -f "${ROOT_DIR}/host/stm32l552/tock/enclave_payload/bin/"*.bin 2>/dev/null || true
    if ! ./rebuild_all.sh >"${BUILD_LOG}" 2>&1; then
        echo "  RESULT: FAIL — rebuild_all.sh failed (last 30 lines):"
        tail -30 "${BUILD_LOG}"
        echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,,,,,,,,,,FAIL_BUILD,${BUILD_LOG},${BUILD_HASH}" >> "${CSV_LOG}"
        exit 1
    fi
    echo "  -- build OK ($(wc -l <"${BUILD_LOG}") lines logged)"
fi

# ── Source settings.sh after build to populate FLASHER/OPENOCD/GDB env ──
source ./settings.sh >/dev/null 2>&1 || true

[ "${MCU_VARIANT}" = "stm32l552" ] || {
    echo "  RESULT: FAIL — MCU_VARIANT must be stm32l552 (got '${MCU_VARIANT}')"
    echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,,,,,,,,,,FAIL_CONFIG,${UART_LOG},${BUILD_HASH}" >> "${CSV_LOG}"
    exit 1
}

# ── Locate ELFs ────────────────────────────────────────────────────────
BOOT_ELF="${ROOT_DIR}/src/hardware/platform/stm32l552/boot/target/thumbv8m.main-none-eabi/release/boot"
HOST_ELF="${ROOT_DIR}/host/stm32l552/tock/bin/tock.elf"

[ -f "${BOOT_ELF}" ] || {
    echo "  RESULT: FAIL — boot ELF missing: ${BOOT_ELF}"
    echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,,,,,,,,,,FAIL_NO_BOOT_ELF,${UART_LOG},${BUILD_HASH}" >> "${CSV_LOG}"
    exit 1
}
[ -f "${HOST_ELF}" ] || {
    echo "  RESULT: FAIL — host ELF missing: ${HOST_ELF}"
    echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,,,,,,,,,,FAIL_NO_HOST_ELF,${UART_LOG},${BUILD_HASH}" >> "${CSV_LOG}"
    exit 1
}

# ── Blob size derivation ───────────────────────────────────────────────
# For fib, the blob lives inside tock.elf (.enclave section); for other
# apps (Step 6+), the blob is host/stm32l552/taclebench/app/<app>.bin.
if [ "${SWEEP_APP}" = "fib" ]; then
    BLOB_SIZE=$(arm-none-eabi-objcopy -O binary --only-section=.enclave \
                "${HOST_ELF}" /tmp/_sweep_fib_blob.bin 2>/dev/null \
                && wc -c < /tmp/_sweep_fib_blob.bin | tr -d ' ' || echo 0)
else
    APP_BIN="${ROOT_DIR}/host/stm32l552/taclebench/app/${SWEEP_APP}.bin"
    if [ -f "${APP_BIN}" ]; then
        BLOB_SIZE=$(wc -c < "${APP_BIN}" | tr -d ' ')
    else
        BLOB_SIZE=0
    fi
fi

# ── State for cleanup ──────────────────────────────────────────────────
#
# Cleanup MUST NOT fail-fast under `set -e`. `kill`/`wait` on an already-
# dead PID returns non-zero, which set -e would treat as a fatal error
# and skip the rest of the cleanup → leaking openocd, holding SWD, and
# blocking the next sweep cell. Every cleanup statement is wrapped in
# `|| true`, with a SIGKILL fallback for openocd in case it ignores
# SIGTERM (observed once on macOS — the GDB extended-remote keepalive
# socket can keep the daemon alive past the first kill).
CAT_PID=""
OOCD_PID=""
cleanup() {
    if [ -n "${CAT_PID}" ]; then
        kill "${CAT_PID}" 2>/dev/null || true
        wait "${CAT_PID}" 2>/dev/null || true
    fi
    if [ -n "${OOCD_PID}" ]; then
        kill "${OOCD_PID}" 2>/dev/null || true
        sleep 0.3
        # SIGKILL fallback if SIGTERM was ignored (process still alive).
        if kill -0 "${OOCD_PID}" 2>/dev/null; then
            kill -9 "${OOCD_PID}" 2>/dev/null || true
        fi
        wait "${OOCD_PID}" 2>/dev/null || true
    fi
    # Belt-and-braces: nuke any stray openocd / cat that might have
    # outlived the named PIDs (e.g., a detached debugger keep-alive).
    pkill -9 -x openocd 2>/dev/null || true
    pkill -9 -f "/dev/cu.usbmodem" 2>/dev/null || true
}
trap cleanup EXIT

# Kill lingering instances that would steal SWD or the UART.
pkill -x openocd 2>/dev/null || true
pkill -f "/dev/cu.usbmodem" 2>/dev/null || true
sleep 1

# ── Start OpenOCD + UART capture ───────────────────────────────────────
echo "  -- start OpenOCD"
"${OPENOCD}" -f "${OPENOCD_CONFIG}" >"${OOCD_LOG}" 2>&1 &
OOCD_PID=$!
sleep 2

if ! (echo > /dev/tcp/localhost/3333) 2>/dev/null; then
    echo "  RESULT: FAIL — OpenOCD didn't open :3333 (tail of log):"
    tail -20 "${OOCD_LOG}"
    echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,${BLOB_SIZE},,,,,,,,,FAIL_OPENOCD,${UART_LOG},${BUILD_HASH}" >> "${CSV_LOG}"
    exit 1
fi

UART=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
[ -n "${UART}" ] || {
    echo "  RESULT: FAIL — no /dev/cu.usbmodem* device"
    echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,${BLOB_SIZE},,,,,,,,,FAIL_NO_UART,${UART_LOG},${BUILD_HASH}" >> "${CSV_LOG}"
    exit 1
}

stty -f "${UART}" 9600 cs8 -parenb -cstopb raw -echo -echoe -echok 2>/dev/null || true
: >"${UART_LOG}"
( cat "${UART}" >>"${UART_LOG}" 2>/dev/null ) &
CAT_PID=$!
sleep 0.5

# ── GDB batch: load boot + host + (optional bench blob) + reset run ────
echo "  -- flash boot + tock host + reset run"
# Erase the NS-flash bench slot region (0x08079000-0x08080000, 28 KB)
# BEFORE flashing the host. Without this, a stale blob from a previous
# cell (different SLOT_SIZE → different meta layout) survives at
# 0x08079000 and crashes the kernel's BFS during the SECOND enclave
# create — observed in Step 6 fib cells where SWEEP_APP=fib never
# flashes a new bench, leaving the previous cell's blob in place
# (which now has incompatible block-header layout).
ERASE_CMD="-ex \"monitor flash erase_address 0x08079000 0x7000\""
EXTRA_FLASH_CMDS=""
if [ "${SWEEP_APP}" != "fib" ]; then
    APP_BIN="${ROOT_DIR}/host/stm32l552/taclebench/app/${SWEEP_APP}.bin"
    if [ -f "${APP_BIN}" ]; then
        EXTRA_FLASH_CMDS="-ex \"monitor flash write_image erase \\\"${APP_BIN}\\\" 0x08079000 bin\""
    fi
fi

eval "${GDB} -batch -nx \
    -ex 'set confirm off' \
    -ex 'set pagination off' \
    -ex 'file ${BOOT_ELF}' \
    -ex 'target extended-remote :3333' \
    -ex 'monitor reset halt' \
    ${ERASE_CMD} \
    -ex 'load' \
    -ex 'monitor reset halt' \
    -ex 'file ${HOST_ELF}' \
    -ex 'load' \
    ${EXTRA_FLASH_CMDS} \
    -ex 'monitor reset run' \
    -ex 'detach' \
    -ex 'quit' \
    >\"${GDB_LOG}\" 2>&1"

if [ $? -ne 0 ]; then
    echo "  RESULT: FAIL — GDB batch returned non-zero (tail of log):"
    tail -30 "${GDB_LOG}"
    echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,${BLOB_SIZE},,,,,,,,,FAIL_GDB,${UART_LOG},${BUILD_HASH}" >> "${CSV_LOG}"
    exit 1
fi

# ── UART capture until "[TOCK] All enclaves done" or timeout ──────────
CAPTURE_SECONDS=${CAPTURE_SECONDS:-90}
echo "  -- capture UART up to ${CAPTURE_SECONDS}s"
DEADLINE=$(( $(date +%s) + CAPTURE_SECONDS ))
MARKER_SEEN=false
while [ $(date +%s) -lt ${DEADLINE} ]; do
    if grep -q "All enclaves done" "${UART_LOG}" 2>/dev/null; then
        sleep 2  # let trailing chars land
        MARKER_SEEN=true
        break
    fi
    sleep 1
done

# Manual cleanup of named PIDs (the trap handler is the safety net).
# `|| true` keeps `set -e` from firing on signaled processes (wait
# returns 128+SIG for SIGTERM/SIGKILL).
kill "${CAT_PID}"  2>/dev/null || true
wait "${CAT_PID}"  2>/dev/null || true
CAT_PID=""
kill "${OOCD_PID}" 2>/dev/null || true
sleep 0.3
if kill -0 "${OOCD_PID}" 2>/dev/null; then
    kill -9 "${OOCD_PID}" 2>/dev/null || true
fi
wait "${OOCD_PID}" 2>/dev/null || true
OOCD_PID=""

if ! ${MARKER_SEEN}; then
    echo "  RESULT: FAIL — 'All enclaves done' not observed within ${CAPTURE_SECONDS}s"
    echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,${BLOB_SIZE},,,,,,,,,FAIL_TIMEOUT,${UART_LOG},${BUILD_HASH}" >> "${CSV_LOG}"
    exit 1
fi

# ── Parse [EVAL_DUMP_BEGIN/END] block ──────────────────────────────────
# Extract only the dump region so we don't accidentally match heartbeat
# or stale UART noise from a previous run.
DUMP=$(awk '/\[EVAL_DUMP_BEGIN\]/,/\[EVAL_DUMP_END\]/' "${UART_LOG}")
if [ -z "${DUMP}" ]; then
    echo "  RESULT: FAIL — no [EVAL_DUMP_BEGIN/END] block in UART log"
    echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,${BLOB_SIZE},,,,,,,,,FAIL_NO_DUMP,${UART_LOG},${BUILD_HASH}" >> "${CSV_LOG}"
    exit 1
fi

# Helpers: pull a single `kind` row's `key=` value out of the DUMP block.
# Wrapped in `|| true` because every `grep`/`head` is allowed to return
# non-zero if the row/key is absent (some builds skip switch/boot rows
# when bench-eval is OFF on the Secure side). Without `|| true` the
# pipefail+set-e combo would silently kill the script halfway through
# parsing and leak openocd — exactly the bug observed in Step 5 v1.
get_field() {
    local kind="$1" key="$2"
    { echo "${DUMP}" | grep -E "^\[EVAL\][[:space:]]+${kind}([[:space:]]|$)" \
        | head -1 \
        | tr '\t' '\n' \
        | grep -E "^${key}=" \
        | head -1 \
        | sed -E "s/^${key}=//"; } || true
}

RUNTIME_CYCLES=$(get_field runtime    cycles)
BOOT_NS_CYCLES=$(get_field boot_ns    cycles)
NULL_SVC_CYCLES=$(get_field null_svc  cycles)
BOOT_SEC_CYCLES=$(get_field boot      sec_cycles)
SWITCH_MIN=$(get_field switch         min)
SWITCH_MEAN=$(get_field switch        mean)
SWITCH_MAX=$(get_field switch         max)
SWITCH_COUNT=$(get_field switch       count)

# Defaults for missing fields so the CSV row is well-formed.
RUNTIME_CYCLES=${RUNTIME_CYCLES:-0x00000000}
BOOT_NS_CYCLES=${BOOT_NS_CYCLES:-0x00000000}
NULL_SVC_CYCLES=${NULL_SVC_CYCLES:-0x00000000}
BOOT_SEC_CYCLES=${BOOT_SEC_CYCLES:-0x00000000}
SWITCH_MIN=${SWITCH_MIN:-0x00000000}
SWITCH_MEAN=${SWITCH_MEAN:-0x00000000}
SWITCH_MAX=${SWITCH_MAX:-0x00000000}
SWITCH_COUNT=${SWITCH_COUNT:-0x00000000}

# ── Append CSV row ─────────────────────────────────────────────────────
echo "${SWEEP_SLOT},${SWEEP_CACHE},${SWEEP_SPEC},${SWEEP_APP},${SWEEP_REP},tock,${BLOB_SIZE},${BOOT_NS_CYCLES},${BOOT_SEC_CYCLES},${RUNTIME_CYCLES},${SWITCH_MIN},${SWITCH_MEAN},${SWITCH_MAX},${SWITCH_COUNT},${NULL_SVC_CYCLES},PASS,${UART_LOG},${BUILD_HASH}" >> "${CSV_LOG}"

echo "  RESULT: PASS"
echo "    runtime=${RUNTIME_CYCLES}  boot_ns=${BOOT_NS_CYCLES}  boot_sec=${BOOT_SEC_CYCLES}"
echo "    switch min=${SWITCH_MIN} mean=${SWITCH_MEAN} max=${SWITCH_MAX} count=${SWITCH_COUNT}"
echo "    null_svc=${NULL_SVC_CYCLES}  blob_size=${BLOB_SIZE}B  uart=${UART_LOG}"
echo "════════════════════════════════════════════════════════════════"
