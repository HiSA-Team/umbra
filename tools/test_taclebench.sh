#!/bin/bash
#
# Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
#
# tools/test_taclebench.sh — end-to-end automated test for TACLeBench
# stateful benchmarks on STM32L552ZE-Q.
#
# Strategy: SEQUENTIAL PASSES (one benchmark at a time).
#
# Why: a 4-enclave round-robin (fib + binarysearch + bsort + countnegative
# all flashed simultaneously) hangs after the first preempt of bsort —
# the next `enter(countnegative)` never returns. This is a known
# multi-enclave-coexistence bug; the MPU-AP=RW fix addressed only the
# data-write half of the symptom. Until that's resolved separately, we
# test each benchmark in isolation alongside fib.
#
# Per pass:
#   - erase NS-flash sectors 240-255 via FLASHER
#   - start OpenOCD (background) + UART cat
#   - one batch GDB session:
#       * load boot ELF
#       * load host ELF (brings fib at 0x08078000)
#       * flash write_image erase <bench>.bin 0x08079000 bin
#       * monitor reset run
#       * detach + quit
#   - wait for "All enclaves done" (early-exit) or capture timeout
#   - stop OpenOCD + cat
#   - assert expected R0 for the benchmark
#
# After all 3 passes succeed, print final PASS.
#
# Expected R0:
#   fib:            0x72CA33A8
#   binarysearch:   0xFFFFFFFF (-1, "key not found in random data")
#   bsort:          0x00000000 (sorted ascending)
#   countnegative:  0x00000000 (matrix balance matches expected)

set -o pipefail

CAPTURE_SECONDS=${CAPTURE_SECONDS:-180}
UART_LOG_BASE=${UART_LOG_BASE:-/tmp/taclebench_uart}
BUILD_LOG=${BUILD_LOG:-/tmp/taclebench_build.log}
OOCD_LOG=${OOCD_LOG:-/tmp/taclebench_openocd.log}
GDB_LOG=${GDB_LOG:-/tmp/taclebench_gdb.log}
CSV_LOG=${CSV_LOG:-/tmp/taclebench_results.csv}

# TACLeBench stateful benchmarks to test sequentially. Override with the
# PHASE5_BENCHES env var (legacy name retained for compatibility).
#
# Default = the three validated stateful benchmarks. To exercise the
# paper-app set (Section §Evaluation), use the magic value `paper`:
#   PHASE5_BENCHES=paper ./tools/test_taclebench.sh
# (Plain `export PAPER_BENCHES=...` from inside the script doesn't reach
# the calling shell, so we expand a magic name here instead.)
PHASE5_BENCHES=${PHASE5_BENCHES:-"binarysearch bsort countnegative"}
if [ "${PHASE5_BENCHES}" = "paper" ]; then
    # Sequential-bench paper apps that fit the current host flash layout.
    # Excluded:
    #   dijkstra — AdjMatrix[100][100] = 10 KB .rodata pushes the
    #              section to 28 KB; protected blob ~35 KB exceeds
    #              the 28 KB NS-flash slot at 0x08079000. Would need
    #              a smaller upstream input or a host-flash-layout
    #              rework. See enclave_blob.ld §reservation comment.
    PHASE5_BENCHES="binarysearch bsort countnegative ndes statemate"
fi
if [ "${PHASE5_BENCHES}" = "validated" ]; then
    PHASE5_BENCHES="binarysearch bsort countnegative"
fi

# Set PHASE5_ALL_AT_ONCE=1 to do a SINGLE pass that flashes fib (bundled
# in host) + all 3 stateful enclaves to distinct NS-flash sectors and
# lets the host round-robin through them. This exercises the multi-
# enclave coexistence path that was hanging before c154152. Ignored
# unless set.
#
# NOTE: After 2026-05-23, MAX_ENCLAVES_CTX was reduced from 4 to 2 to
# accommodate the 8 KB per-enclave PSP stack needed for paper-app
# `ndes`. The host's main.c still scans up to 4 NS-flash slots, but
# the kernel can only register 2 enclaves at a time — the 3rd and
# 4th `umbra_enclave_create` calls fail with 0xFFFF_FFF3. This mode
# is left in place for regression testing but expect failures with
# more than 2 enclaves flashed.
PHASE5_ALL_AT_ONCE=${PHASE5_ALL_AT_ONCE:-0}

cd "$(dirname "$0")/.."
ROOT_DIR=$(pwd)

# ── State for cleanup ──────────────────────────────────────────────────
CAT_PID=""
OOCD_PID=""

cleanup() {
    [ -n "${CAT_PID}"  ] && kill "${CAT_PID}"  2>/dev/null
    [ -n "${OOCD_PID}" ] && kill "${OOCD_PID}" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

die() {
    cleanup
    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "  FAIL: $*"
    echo "════════════════════════════════════════════════════════════════"
    exit 1
}

# ── Step 1: source settings.sh ─────────────────────────────────────────
echo "==> [1/N] source settings.sh"
# shellcheck disable=SC1091
source ./settings.sh || true

# settings.sh exports UMBRA_CHAINED=1 but NOT UMBRA_ESS_MISS_RECOVERY=1
# — the latter is set inside rebuild_all.sh before its `make`. Our
# auto-build step below also calls `make`, so we need the same env or
# protect_enclave.py emits a chained-only blob (288 B/block) that the
# ess_miss_recovery-enabled kernel can't parse (it reads 320 B/block,
# misaligns the meta, and rejects the blob with `chained-measurement
# FAIL`). Export it here so the auto-build matches the kernel's layout.
export UMBRA_ESS_MISS_RECOVERY=1

[ "${MCU_VARIANT}" = "stm32l552" ] || \
    die "MCU_VARIANT must be stm32l552 (got '${MCU_VARIANT}')"

# HOST_APP plumbing — settings.sh already exports HOST_APP.
case "${HOST_APP:-bare_metal}" in
    bare_metal)  HOST_LOG_PREFIX="[USER]" ;;
    freertos)    HOST_LOG_PREFIX="[FREERTOS]" ;;
    tock)        HOST_LOG_PREFIX="[TOCK]" ;;
    *)           die "Unsupported HOST_APP=${HOST_APP} for taclebench harness (expected bare_metal, freertos, or tock)" ;;
esac
echo "==> HOST_APP=${HOST_APP:-bare_metal} (HOST_LOG_PREFIX='${HOST_LOG_PREFIX}')"

[ -n "${FLASHER}"    ] || die "FLASHER not set"
[ -n "${PORT_NAME}"  ] || die "PORT_NAME not set"
[ -n "${OPENOCD}"    ] || die "OPENOCD not set"
[ -n "${GDB}"        ] || die "GDB not set"
[ -n "${OPENOCD_CONFIG}" ] || die "OPENOCD_CONFIG not set"

# Kill any lingering openocd so we own the SWD interface.
if pgrep -x openocd >/dev/null; then
    echo "    (killing lingering openocd processes)"
    pkill -x openocd 2>/dev/null || true
    sleep 1
fi

# Aggressively free the UART device — kill anything whose command line
# touches /dev/cu.usbmodem (cat, screen, picocom, minicom, etc.). The
# old `pkill -f "cat /dev/cu.usbmodem"` only caught one variant.
pkill -f "/dev/cu.usbmodem" 2>/dev/null || true
sleep 0.5

# If a serial monitor inside an IDE (Arduino IDE, VS Code Serial
# Monitor extension, STM32CubeProgrammer, etc.) is holding the device,
# pkill won't reach it. Detect with `lsof` and tell the user.
UART_PROBE=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
if [ -n "${UART_PROBE}" ] && command -v lsof >/dev/null 2>&1; then
    HOLDERS=$(lsof -t "${UART_PROBE}" 2>/dev/null | head -5)
    if [ -n "${HOLDERS}" ]; then
        echo
        echo "════════════════════════════════════════════════════════════════"
        echo "  FAIL: ${UART_PROBE} is held by another process"
        echo "════════════════════════════════════════════════════════════════"
        echo "  Holders (PID + command):"
        lsof "${UART_PROBE}" 2>/dev/null | sed 's/^/    /'
        echo
        echo "  Close the holder (likely your IDE's serial monitor or a"
        echo "  leftover 'screen'/'picocom' session) and re-run."
        echo "════════════════════════════════════════════════════════════════"
        exit 1
    fi
fi

# ── Step 2: build (once for all passes) ────────────────────────────────
echo "==> [2/N] rebuild_all.sh (build + re-sign all taclebench blobs)"
if ! ./rebuild_all.sh >"${BUILD_LOG}" 2>&1; then
    echo "FAIL: rebuild_all.sh failed"
    tail -50 "${BUILD_LOG}"
    exit 1
fi
echo "    OK ($(wc -l <"${BUILD_LOG}") lines logged to ${BUILD_LOG})"

if ! grep -q "Detected Code+Data Length" "${BUILD_LOG}"; then
    die "build log doesn't show 'Detected Code+Data Length' — linker symbol missing"
fi

# Initialise the CSV results file with a header row. Each pass appends
# one line. The CSV can be fed directly to a plotting tool (gnuplot,
# matplotlib, etc.) to produce the paper's runtime-overhead chart.
echo "bench,host_app,blob_size_bytes,pass_fail,wall_clock_seconds,uart_bytes,heartbeat_count,drift_max_cycles,healthy_pct" >"${CSV_LOG}"

BOOT_ELF="${ROOT_DIR}/src/hardware/platform/stm32l552/boot/target/thumbv8m.main-none-eabi/release/boot"
HOST_ELF="${ROOT_DIR}/host/stm32l552/${HOST_APP}/bin/${HOST_APP}.elf"
APP_DIR="${ROOT_DIR}/host/stm32l552/taclebench/app"

[ -f "${BOOT_ELF}" ] || die "boot ELF missing: ${BOOT_ELF}"
[ -f "${HOST_ELF}" ] || die "host ELF missing: ${HOST_ELF}"

# Auto-build any requested benches that aren't in `all`. rebuild_all.sh
# only builds the validated benchmarks (`make all` in
# host/stm32l552/taclebench); the paper apps (ndes/dijkstra/statemate)
# live in host/stm32l552/taclebench/blob_src/ with explicit Makefile
# targets but aren't in `all` until validated. Build them on demand here.
for bench in ${PHASE5_BENCHES}; do
    if [ ! -f "${APP_DIR}/${bench}.bin" ]; then
        echo "    -- ${bench}.bin missing; building..."
        if ! make -C "${ROOT_DIR}/host/stm32l552/taclebench" "${bench}" >>"${BUILD_LOG}" 2>&1; then
            echo "FAIL: build of ${bench} failed — see ${BUILD_LOG}"
            tail -40 "${BUILD_LOG}"
            exit 1
        fi
    fi
    [ -f "${APP_DIR}/${bench}.bin" ] || die "${bench}.bin still missing after build"
done

# ── Per-pass function ──────────────────────────────────────────────────
#
# Args: $1 = benchmark name, $2 = expected R0 (8-hex-digit string, upper).
# Returns 0 on PASS, 1 on FAIL. Updates UART_LOG_BASE_${name}.log.
run_pass() {
    local bench="$1"
    local expected_r0="$2"
    local UART_LOG="${UART_LOG_BASE}_${bench}.log"

    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "  PASS: ${bench}  (expected R0=${expected_r0})"
    echo "════════════════════════════════════════════════════════════════"

    # Erase NS-flash range before each pass — wipes the previous bench's
    # blob plus any stale leftovers.
    echo "  -- erase NS-flash sectors 240-255"
    for sec in 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255; do
        "${FLASHER}" -c port="${PORT_NAME}" --erase "${sec}" "${sec}" \
            >/dev/null 2>&1 || true
    done

    # Start OpenOCD.
    echo "  -- start OpenOCD"
    "${OPENOCD}" -f "${OPENOCD_CONFIG}" >"${OOCD_LOG}" 2>&1 &
    OOCD_PID=$!
    sleep 2

    if ! (echo > /dev/tcp/localhost/3333) 2>/dev/null; then
        echo "OpenOCD log tail:"
        tail -20 "${OOCD_LOG}"
        die "OpenOCD failed to start on :3333"
    fi

    # Start UART capture.
    echo "  -- start UART capture"
    UART=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
    [ -n "${UART}" ] || die "no /dev/cu.usbmodem* device"

    stty -f "${UART}" 9600 cs8 -parenb -cstopb raw -echo -echoe -echok 2>/dev/null || true
    : >"${UART_LOG}"
    local CAT_ERR=/tmp/taclebench_cat.err
    : >"${CAT_ERR}"
    ( cat "${UART}" >>"${UART_LOG}" 2>>"${CAT_ERR}" ) &
    CAT_PID=$!
    sleep 0.5

    # Verify cat actually opened the device. If it died (e.g., "Resource
    # busy"), the UART log stays empty for the entire capture window and
    # the test silently fails. Catch it now.
    if ! kill -0 "${CAT_PID}" 2>/dev/null; then
        echo "FAIL: cat ${UART} died immediately. Tail of stderr:"
        sed 's/^/  /' "${CAT_ERR}"
        die "UART capture failed to start — close any serial monitor on ${UART}"
    fi

    # Capture blob size for the CSV row.
    local blob_size
    blob_size=$(wc -c < "${APP_DIR}/${bench}.bin" 2>/dev/null | tr -d ' ' || echo "0")

    # Batch GDB: load boot + host + one bench, reset run.
    echo "  -- flash boot + host + ${bench} + reset run"
    "${GDB}" -batch -nx \
        -ex 'set confirm off' \
        -ex 'set pagination off' \
        -ex "file ${BOOT_ELF}" \
        -ex 'target extended-remote :3333' \
        -ex 'monitor reset halt' \
        -ex "load" \
        -ex 'monitor reset halt' \
        -ex "file ${HOST_ELF}" \
        -ex "load" \
        -ex "monitor flash write_image erase \"${APP_DIR}/${bench}.bin\" 0x08079000 bin" \
        -ex 'monitor reset run' \
        -ex 'detach' \
        -ex 'quit' \
        >"${GDB_LOG}" 2>&1
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
        echo "GDB batch returned non-zero (${rc}). Tail of GDB log:"
        tail -40 "${GDB_LOG}"
        die "GDB batch flash sequence failed"
    fi

    # ── Wall-clock timing: start AFTER GDB releases the chip with `reset
    # run`, end when "All enclaves done" appears in UART. This is the
    # script-side host-to-chip wall clock, not chip-cycle-accurate, but
    # consistent across runs and good enough for relative overhead plots.
    local T_start
    T_start=$(date +%s)

    # Wait for "All enclaves done" (early-exit) or timeout.
    echo "  -- capture UART up to ${CAPTURE_SECONDS}s (early-exit on 'All enclaves done')"
    local deadline=$(( T_start + CAPTURE_SECONDS ))
    local marker_seen=false
    while [ $(date +%s) -lt ${deadline} ]; do
        if grep -q "All enclaves done" "${UART_LOG}" 2>/dev/null; then
            sleep 2  # let trailing chars land
            marker_seen=true
            break
        fi
        sleep 1
    done

    # Stop cat + OpenOCD.
    kill "${CAT_PID}"  2>/dev/null; wait "${CAT_PID}"  2>/dev/null
    CAT_PID=""
    kill "${OOCD_PID}" 2>/dev/null; wait "${OOCD_PID}" 2>/dev/null
    OOCD_PID=""

    # Compute wall-clock runtime; if the marker was never observed,
    # T_runtime = capture window (worst case for plotting).
    local T_end=$(date +%s)
    local T_runtime=$(( T_end - T_start ))
    local uart_bytes=$(wc -c <"${UART_LOG}" | tr -d ' ')

    echo "  -- captured ${uart_bytes} bytes in ${T_runtime}s"

    # Validate.
    local pass=true
    local failures=()

    grep -qF "Kernel Initialized" "${UART_LOG}" || \
        { failures+=("missing Kernel Initialized"); pass=false; }
    # NS-world liveness marker. bare_metal NS prints "[USER]" on every state
    # transition; freertos NS prints "[FREERTOS]". Matching the prefix is
    # semantically equivalent to the old "Hello Non-Secure World!" check
    # for bare_metal (that string is the first [USER] line printed).
    grep -qF "${HOST_LOG_PREFIX}" "${UART_LOG}" || \
        { failures+=("missing ${HOST_LOG_PREFIX} marker (NS world not alive)"); pass=false; }
    grep -qF "chained-measurement FAIL" "${UART_LOG}" && \
        { failures+=("FORBIDDEN: chained-measurement FAIL"); pass=false; }
    grep -qF "[MemManage] Handler Reached" "${UART_LOG}" && \
        { failures+=("FORBIDDEN: MemManage panic"); pass=false; }
    grep -qF "[HardFault]" "${UART_LOG}" && \
        { failures+=("FORBIDDEN: HardFault"); pass=false; }

    # Expect exactly 2 chained-measurement OK (fib + bench).
    local ok_count
    ok_count=$(grep -c "chained-measurement OK" "${UART_LOG}" || true)
    if [ "${ok_count}" -lt 2 ]; then
        failures+=("only ${ok_count} chained-measurement OK lines (expected >=2)")
        pass=false
    fi

    # fib R0 always present.
    grep -qF "R0=0x72CA33A8" "${UART_LOG}" || \
        { failures+=("missing fib R0=0x72CA33A8"); pass=false; }

    # Bench-specific R0.
    grep -qF "R0=0x${expected_r0}" "${UART_LOG}" || \
        { failures+=("missing ${bench} R0=0x${expected_r0}"); pass=false; }

    # FreeRTOS-only assertions: heartbeat liveness + DWT drift bounds.
    local DRIFT_MAX_HEX="" B0_HEX="" B1_HEX="" B2_HEX="" B3_HEX="" B4_HEX="" B5_HEX=""
    local B0=0 B1=0 B2=0 B3=0 B4=0 B5=0 TOTAL=0 HEALTHY=0
    local HEARTBEAT_COUNT=0
    local DRIFT_MAX_DEC=0
    local HEALTHY_PCT=0
    if [ "${HOST_APP:-bare_metal}" = "freertos" ] || [ "${HOST_APP:-bare_metal}" = "tock" ]; then
        # Heartbeat liveness: >=5 [HEARTBEAT] over the run.
        # Heartbeat is vTaskDelay(100 ms FreeRTOS) → ~325 ms wall under
        # enclave load (effective NS tick rate ~250-300 Hz).
        HEARTBEAT_COUNT=$(grep -c "\[HEARTBEAT" "${UART_LOG}" || true)
        if [ "${HEARTBEAT_COUNT}" -lt 5 ]; then
            failures+=("only ${HEARTBEAT_COUNT} heartbeats (expected >=5)")
            pass=false
        fi

        # Drift max bound: < 6_600_000 cycles (= 60 ms @ 110 MHz). Bound
        # is dominated by the longest NS taskENTER_CRITICAL section in
        # vEnclaveTask — the "[FREERTOS] Enclave terminated! R0=0xHHHHHHHH\n"
        # print (45 chars × ~1ms/char at 9600 baud ≈ 47 ms). Critical
        # sections around umbra_enclave_create were intentionally dropped
        # to keep drift bounded; Secure-side prints inside enclave_create
        # may interleave with NS heartbeat as a consequence. 98%+ of ticks
        # land in healthy buckets (delta < 10× expected). UART format:
        # "[DRIFT] max=0xHHHHHHHH total=0xHHHHHHHH".
        # Match the first [DRIFT] max= line (the end-of-run snapshot is
        # printed exactly once by vEnclaveTask before vTaskDelete).
        DRIFT_MAX_HEX=$(LC_ALL=C awk '/\[DRIFT\] max=/ {
            for (i=1; i<=NF; i++) if ($i ~ /^max=/) { sub(/^max=/, "", $i); print $i; exit }
        }' "${UART_LOG}" | head -1)
        if [ -n "${DRIFT_MAX_HEX}" ]; then
            DRIFT_MAX_DEC=$(printf '%d' "${DRIFT_MAX_HEX}" 2>/dev/null || echo 0)
            if [ "${DRIFT_MAX_DEC}" -ge 6600000 ]; then
                failures+=("drift max=${DRIFT_MAX_HEX} (= ${DRIFT_MAX_DEC} cycles) exceeds 6600000 (60 ms)")
                pass=false
            fi
        else
            failures+=("missing [DRIFT] max= line in UART log")
            pass=false
        fi

        # Distribution: b0+b1+b2+b3 (delta < 10× expected) >= 70% of ticks.
        # Format: "[DRIFT] b0=0xHHH b1=0xHHH b2=0xHHH b3=0xHHH b4=0xHHH b5=0xHHH"
        # Parse with process substitution + read (no eval, no shell injection).
        # awk-side regex validates each token is `bN=0xHHH...` before emitting.
        read -r B0_HEX B1_HEX B2_HEX B3_HEX B4_HEX B5_HEX < <(LC_ALL=C awk '
            /\[DRIFT\] b0=/ {
                delete v
                for (i=1; i<=NF; i++)
                    if (match($i, /^b[0-5]=0x[0-9A-Fa-f]+$/))
                        v[substr($i,1,2)] = substr($i,4)
                print v["b0"], v["b1"], v["b2"], v["b3"], v["b4"], v["b5"]
                exit
            }' "${UART_LOG}")
        if [ -n "${B0_HEX}" ]; then
            B0=$(printf '%d' "${B0_HEX}" 2>/dev/null || echo 0)
            B1=$(printf '%d' "${B1_HEX}" 2>/dev/null || echo 0)
            B2=$(printf '%d' "${B2_HEX}" 2>/dev/null || echo 0)
            B3=$(printf '%d' "${B3_HEX}" 2>/dev/null || echo 0)
            B4=$(printf '%d' "${B4_HEX}" 2>/dev/null || echo 0)
            B5=$(printf '%d' "${B5_HEX}" 2>/dev/null || echo 0)
            TOTAL=$((B0+B1+B2+B3+B4+B5))
            HEALTHY=$((B0+B1+B2+B3))
            if [ "${TOTAL}" -gt 0 ]; then
                HEALTHY_PCT=$((HEALTHY * 100 / TOTAL))
                if [ "${HEALTHY_PCT}" -lt 70 ]; then
                    failures+=("only ${HEALTHY}/${TOTAL} (${HEALTHY_PCT}%) ticks in healthy buckets b0-b3 (<70%)")
                    pass=false
                fi
            else
                failures+=("[DRIFT] buckets all zero — tick hook not firing?")
                pass=false
            fi
        else
            failures+=("missing [DRIFT] b0= line in UART log")
            pass=false
        fi
    fi

    # Done marker.
    if ! ${marker_seen}; then
        failures+=("'All enclaves done' not observed within ${CAPTURE_SECONDS}s")
        pass=false
    fi

    # Append CSV row (one per pass). Fields:
    #   bench, host_app, blob_size_bytes, pass_fail, wall_clock_seconds, uart_bytes,
    #   heartbeat_count, drift_max_cycles, healthy_pct
    local pf
    if ${pass}; then pf="PASS"; else pf="FAIL"; fi
    echo "${bench},${HOST_APP:-bare_metal},${blob_size},${pf},${T_runtime},${uart_bytes},${HEARTBEAT_COUNT},${DRIFT_MAX_DEC},${HEALTHY_PCT}" >>"${CSV_LOG}"

    if ${pass}; then
        echo "  RESULT: PASS for ${bench}  (runtime ${T_runtime}s, blob ${blob_size}B)"
        return 0
    else
        echo "  RESULT: FAIL for ${bench}"
        for f in "${failures[@]}"; do
            echo "    - ${f}"
        done
        echo "  UART log: ${UART_LOG}"
        return 1
    fi
}

# ── Helper: expected R0 lookup (bash 3.x compatible) ───────────────────
#
# Plain `case` function instead of `declare -A` so we work on bash 3.x
# (macOS default) as well as bash 4+. Add a row here when porting a new
# benchmark.
expected_r0_for() {
    case "$1" in
        binarysearch)  echo "FFFFFFFF" ;;
        bsort)         echo "00000000" ;;
        countnegative) echo "00000000" ;;
        recursion)     echo "00000000" ;;
        fac)           echo "00000000" ;;
        prime)         echo "00000000" ;;
        # Paper apps from lib/tacle-bench/bench/sequential/. R0 values
        # are upstream-defined: 0 = passed reference check, non-zero =
        # mismatch. Verify each individually on first hardware run; the
        # values below are upstream expectations.
        ndes)          echo "00000000" ;;
        dijkstra)      echo "00000000" ;;
        statemate)     echo "00000000" ;;
        *)             echo "" ;;
    esac
}

# ── All-at-once pass: fib + every stateful enclave flashed simultaneously
#
# Flashes fib (bundled in host) + binarysearch/bsort/countnegative to
# 0x08079000/0x0807A000/0x0807B000 respectively. Host (stm32l552/bare_metal)
# round-robins through all 4 with MAX_ENCLAVES=4 enclave_ids[]. Validates
# all 4 expected R0 values + final "All enclaves done" appear in one
# trace. Exercises the multi-enclave coexistence path that the original
# "multi-enclave residual bug" was attributed to before commit c154152 fixed
# the DMA slot-leak that was the actual cause.
run_all_at_once_pass() {
    if [ "${HOST_APP:-bare_metal}" = "freertos" ]; then
        die "PHASE5_ALL_AT_ONCE=1 not supported with HOST_APP=freertos (use sequential per-bench passes; drift assertions are bench-specific)"
    fi
    local UART_LOG="${UART_LOG_BASE}_allatonce.log"

    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "  ALL-AT-ONCE PASS: fib + binarysearch + bsort + countnegative"
    echo "════════════════════════════════════════════════════════════════"

    echo "  -- erase NS-flash sectors 240-255"
    for sec in 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255; do
        "${FLASHER}" -c port="${PORT_NAME}" --erase "${sec}" "${sec}" \
            >/dev/null 2>&1 || true
    done

    echo "  -- start OpenOCD"
    "${OPENOCD}" -f "${OPENOCD_CONFIG}" >"${OOCD_LOG}" 2>&1 &
    OOCD_PID=$!
    sleep 2

    if ! (echo > /dev/tcp/localhost/3333) 2>/dev/null; then
        tail -20 "${OOCD_LOG}"
        die "OpenOCD failed to start on :3333"
    fi

    echo "  -- start UART capture"
    UART=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
    [ -n "${UART}" ] || die "no /dev/cu.usbmodem* device"

    stty -f "${UART}" 9600 cs8 -parenb -cstopb raw -echo -echoe -echok 2>/dev/null || true
    : >"${UART_LOG}"
    local CAT_ERR=/tmp/taclebench_cat.err
    : >"${CAT_ERR}"
    ( cat "${UART}" >>"${UART_LOG}" 2>>"${CAT_ERR}" ) &
    CAT_PID=$!
    sleep 0.5
    if ! kill -0 "${CAT_PID}" 2>/dev/null; then
        echo "FAIL: cat ${UART} died immediately. Tail of stderr:"
        sed 's/^/  /' "${CAT_ERR}"
        die "UART capture failed to start — close any serial monitor on ${UART}"
    fi

    echo "  -- flash boot + host + ALL stateful enclaves + reset run"
    "${GDB}" -batch -nx \
        -ex 'set confirm off' \
        -ex 'set pagination off' \
        -ex "file ${BOOT_ELF}" \
        -ex 'target extended-remote :3333' \
        -ex 'monitor reset halt' \
        -ex "load" \
        -ex 'monitor reset halt' \
        -ex "file ${HOST_ELF}" \
        -ex "load" \
        -ex "monitor flash write_image erase \"${APP_DIR}/binarysearch.bin\" 0x08079000 bin" \
        -ex "monitor flash write_image erase \"${APP_DIR}/bsort.bin\" 0x0807A000 bin" \
        -ex "monitor flash write_image erase \"${APP_DIR}/countnegative.bin\" 0x0807B000 bin" \
        -ex 'monitor reset run' \
        -ex 'detach' \
        -ex 'quit' \
        >"${GDB_LOG}" 2>&1
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
        tail -40 "${GDB_LOG}"
        die "GDB batch flash sequence failed"
    fi

    # All-at-once needs MUCH more time because of round-robin overhead
    # (countnegative + bsort both preempt many times sharing windows).
    local timeout=${CAPTURE_SECONDS}
    echo "  -- capture UART up to ${timeout}s (early-exit on 'All enclaves done')"
    local deadline=$(( $(date +%s) + timeout ))
    local marker_seen=false
    while [ $(date +%s) -lt ${deadline} ]; do
        if grep -q "All enclaves done" "${UART_LOG}" 2>/dev/null; then
            sleep 2
            marker_seen=true
            break
        fi
        sleep 1
    done

    kill "${CAT_PID}"  2>/dev/null; wait "${CAT_PID}"  2>/dev/null
    CAT_PID=""
    kill "${OOCD_PID}" 2>/dev/null; wait "${OOCD_PID}" 2>/dev/null
    OOCD_PID=""

    echo "  -- captured $(wc -c <"${UART_LOG}") bytes"

    local pass=true
    local failures=()

    grep -qF "Kernel Initialized" "${UART_LOG}" || \
        { failures+=("missing Kernel Initialized"); pass=false; }
    grep -qF "${HOST_LOG_PREFIX}" "${UART_LOG}" || \
        { failures+=("missing ${HOST_LOG_PREFIX} marker (NS world not alive)"); pass=false; }
    grep -qF "chained-measurement FAIL" "${UART_LOG}" && \
        { failures+=("FORBIDDEN: chained-measurement FAIL"); pass=false; }
    grep -qF "[MemManage] Handler Reached" "${UART_LOG}" && \
        { failures+=("FORBIDDEN: MemManage panic"); pass=false; }
    grep -qF "[HardFault]" "${UART_LOG}" && \
        { failures+=("FORBIDDEN: HardFault"); pass=false; }

    # Expect 4 chained-measurement OK (fib + 3 stateful).
    local ok_count
    ok_count=$(grep -c "chained-measurement OK" "${UART_LOG}" || true)
    if [ "${ok_count}" -lt 4 ]; then
        failures+=("only ${ok_count} chained-measurement OK lines (expected >=4)")
        pass=false
    fi

    # All 4 R0 values must appear.
    grep -qF "R0=0x72CA33A8" "${UART_LOG}" || \
        { failures+=("missing fib R0=0x72CA33A8"); pass=false; }
    grep -qF "R0=0xFFFFFFFF" "${UART_LOG}" || \
        { failures+=("missing binarysearch R0=0xFFFFFFFF"); pass=false; }
    # bsort + countnegative both R0=0 → need >=2 occurrences.
    local zero_count
    zero_count=$(grep -c "R0=0x00000000" "${UART_LOG}" || true)
    if [ "${zero_count}" -lt 2 ]; then
        failures+=("only ${zero_count} R0=0x00000000 (expected >=2 for bsort + countnegative)")
        pass=false
    fi

    if ! ${marker_seen}; then
        failures+=("'All enclaves done' not observed within ${timeout}s")
        pass=false
    fi

    if ${pass}; then
        echo "  RESULT: PASS for all-at-once"
        return 0
    else
        echo "  RESULT: FAIL for all-at-once"
        for f in "${failures[@]}"; do
            echo "    - ${f}"
        done
        echo "  UART log: ${UART_LOG}"
        return 1
    fi
}

# ── Dispatch: all-at-once OR sequential per-bench ──────────────────────
ALL_PASS=true
SUMMARY=()

if [ "${PHASE5_ALL_AT_ONCE}" = "1" ]; then
    if run_all_at_once_pass; then
        SUMMARY+=("all-at-once (fib + 3 stateful): PASS")
    else
        SUMMARY+=("all-at-once (fib + 3 stateful): FAIL")
        ALL_PASS=false
    fi
else
    for bench in ${PHASE5_BENCHES}; do
        expected=$(expected_r0_for "${bench}")
        if [ -z "${expected}" ]; then
            SUMMARY+=("${bench}: SKIP (no expected R0 mapping)")
            continue
        fi
        if run_pass "${bench}" "${expected}"; then
            SUMMARY+=("${bench}: PASS (R0=0x${expected})")
        else
            SUMMARY+=("${bench}: FAIL")
            ALL_PASS=false
        fi
    done
fi

# ── Final summary ──────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════"
echo "  FINAL SUMMARY"
echo "════════════════════════════════════════════════════════════════"
for line in "${SUMMARY[@]}"; do
    echo "  ${line}"
done
echo

# Pretty-print the CSV table (column-aligned) so the user can eyeball
# results without opening the file. Skips the header line.
if [ -s "${CSV_LOG}" ]; then
    echo "  ── Per-bench results table ──"
    column -t -s, "${CSV_LOG}" 2>/dev/null | sed 's/^/  /'
    echo
    echo "  CSV results: ${CSV_LOG}"
fi
echo

if ${ALL_PASS}; then
    echo "  RESULT: ALL PASSES SUCCESS"
    echo "════════════════════════════════════════════════════════════════"
    exit 0
else
    echo "  RESULT: ONE OR MORE PASSES FAILED"
    echo "  Per-bench UART logs: ${UART_LOG_BASE}_*.log"
    echo "════════════════════════════════════════════════════════════════"
    exit 1
fi
