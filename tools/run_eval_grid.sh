#!/bin/bash
#
# Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
#
#
# Iterates the full (slot × cache × spec × app × rep) grid invoking
# `run_eval_sweep.sh` per cell. Optimised with L1 iteration order
# (build-outer, app-inner): the secure kernel + host are rebuilt ONCE
# per (slot, cache, spec) config and reused across all apps+reps for
# that config. Without this the ~30s build cost × ~1500 cells = 12.5 h
# of pure build time; with this it drops to ~46 builds × 30s ≈ 23 min.
#
# Grid (Q6b from grilling):
#   SLOT  ∈ {1024, 2048, 4096, 8192}     — EFBC block plaintext size
#   CACHE ∈ {0, 1, 2, 4, 8, 16}          — ESS entries (0 = cache-zero-mode)
#   SPEC  ∈ {0, 1}                       — DMA prefetch on/off
#   APPS  = fib + paper-fidelity + Tier-1 extensions
#   REPS  = 3 (N=3 from Q7a, median + min/max in CSV)
#
# Filter: `slot * cache > ESS_SIZE` cells are skipped (cache=16 +
# slot=8192 = 128 KB > 64 KB ESS), so 4×6×2 = 48 builds minus 1 invalid
# combo (slot=8192,cache=16) = 47 build configs. ~1500 cells total at
# N=3 reps. Plain idempotent CSV survives crashes/reboots — re-running
# resumes from the last completed cell.
#
# Usage:
#   ./tools/run_eval_grid.sh                 # full grid, defaults
#   SWEEP_REPS=1 ./tools/run_eval_grid.sh    # quick test, 1 rep per cell
#   SWEEP_APPS="fib bsort" SWEEP_REPS=1 \    # subset for validation
#     ./tools/run_eval_grid.sh

set -eo pipefail
set +m                                 # suppress "Terminated: 15" notices
export LC_ALL=C                        # byte-locale for awk/grep/sed

# Blob protection layout knobs — MUST match the kernel build (which has
# `chained_measurement` + `ess_miss_recovery` features enabled by default).
# `rebuild_all.sh` sets these for its OWN subshell, but the env vars don't
# leak back to the grid wrapper, so subsequent `make -C taclebench
# eval_apps` calls would use protect_enclave.py defaults (chained only,
# 32-byte block header) and produce blobs the kernel can't parse — meta
# bytes appear shifted, the count field reads as garbage, and
# `api_impl.rs:170` panics with "Block reachable count exceeds
# MAX_REACHABLE". Export them here so both children inherit them.
export UMBRA_CHAINED=1
export UMBRA_ESS_MISS_RECOVERY=1

# ── Grid knobs (override via env) ─────────────────────────────────────
SWEEP_SLOTS=${SWEEP_SLOTS:-"1024 2048 4096 8192"}
SWEEP_CACHES=${SWEEP_CACHES:-"0 1 2 4 8 16"}
SWEEP_SPECS=${SWEEP_SPECS:-"0 1"}
SWEEP_REPS=${SWEEP_REPS:-3}

# PM scope (Step 0b): paper-fidelity + Tier-1 + fib bundled. Order
# matters for early-fail visibility — put the cheap apps first so a
# busted harness fails in seconds, not minutes. Heavy apps last.
SWEEP_APPS=${SWEEP_APPS:-"fib insertsort crc bsort countnegative \
                          md5 ndes adpcm_dec petrinet \
                          statemate dijkstra anagram cjpeg_wrbmp"}

# Per-bench .bin location (Step 0a–0c output). The grid script builds
# these once per config along with the kernel.
TACLE_DIR=host/stm32l552/taclebench
TACLE_BIN_DIR=${TACLE_DIR}/app

# ── ESS_SIZE = 64KB; filter invalid (slot × cache > 64KB) combos ──────
ESS_SIZE_BYTES=$((64 * 1024))

is_valid_combo() {
    local slot=$1 cache=$2
    # cache=0 always valid (cache-zero-mode handles it).
    [ "${cache}" = "0" ] && return 0
    # Otherwise enforce slot × cache ≤ ESS_SIZE.
    [ $((slot * cache)) -le ${ESS_SIZE_BYTES} ]
}

# ── Logs + CSV (mirror run_eval_sweep.sh defaults: $PWD-relative) ─────
INVOCATION_DIR=${PWD}
GRID_LOG=${GRID_LOG:-${INVOCATION_DIR}/grid_progress.log}

# ── Pre-count cells for progress reporting ────────────────────────────
N_CONFIGS=0
N_CELLS=0
for slot in ${SWEEP_SLOTS}; do
    for cache in ${SWEEP_CACHES}; do
        is_valid_combo "${slot}" "${cache}" || continue
        for spec in ${SWEEP_SPECS}; do
            N_CONFIGS=$((N_CONFIGS + 1))
            for app in ${SWEEP_APPS}; do
                for rep in $(seq 0 $((SWEEP_REPS - 1))); do
                    N_CELLS=$((N_CELLS + 1))
                done
            done
        done
    done
done

echo "════════════════════════════════════════════════════════════════"
echo "  Evaluation full sweep grid"
echo "════════════════════════════════════════════════════════════════"
echo "  Slots:    ${SWEEP_SLOTS}"
echo "  Caches:   ${SWEEP_CACHES}"
echo "  Specs:    ${SWEEP_SPECS}"
echo "  Apps:     ${SWEEP_APPS}"
echo "  Reps:     ${SWEEP_REPS}"
echo "  Builds:   ${N_CONFIGS}  (~30s each ≈ $((N_CONFIGS * 30 / 60)) min)"
echo "  Cells:    ${N_CELLS}    (~40s each ≈ $((N_CELLS * 40 / 60)) min)"
echo "  ETA:      ~$(( (N_CONFIGS * 30 + N_CELLS * 40) / 3600 )) h"
echo "  Logs:     ${GRID_LOG} + per-cell uart/build under ./eval_logs/"
echo "════════════════════════════════════════════════════════════════"

START_EPOCH=$(date +%s)
CELL_IDX=0
CELL_PASS=0
CELL_FAIL=0
CELL_SKIP=0

# ── Outer loop: build-outer (L1) ──────────────────────────────────────
for slot in ${SWEEP_SLOTS}; do
    for cache in ${SWEEP_CACHES}; do
        if ! is_valid_combo "${slot}" "${cache}"; then
            continue
        fi
        for spec in ${SWEEP_SPECS}; do
            echo
            echo "================================================================"
            echo "  CONFIG slot=${slot} cache=${cache} spec=${spec}"
            echo "================================================================"

            # Build kernel + host + ALL bench .bin once for this config.
            # Set env so .cargo/config.toml [env] takes effect.
            export UMBRA_SLOT_SIZE_BYTES="${slot}"
            if [ "${cache}" = "0" ]; then
                export UMBRA_CACHE_LIMIT=64
                export UMBRA_CACHE_ZERO_MODE=1
            else
                export UMBRA_CACHE_LIMIT="${cache}"
                unset UMBRA_CACHE_ZERO_MODE
            fi
            export UMBRA_BENCH_EVAL=1
            if [ "${spec}" = "0" ]; then
                export UMBRA_SPECULATION=0
            else
                unset UMBRA_SPECULATION
            fi

            echo "  -- rebuild kernel + host (UMBRA_SLOT=${slot} CACHE=${cache} SPEC=${spec} CACHE_ZERO=${UMBRA_CACHE_ZERO_MODE:-0})"
            CONFIG_BUILD_LOG="${INVOCATION_DIR}/eval_logs/grid_build_slot${slot}_cache${cache}_spec${spec}.log"
            mkdir -p "${INVOCATION_DIR}/eval_logs"
            # rm enclave_payload bin to defeat make staleness (Step 4 trace).
            rm -f host/stm32l552/tock/enclave_payload/bin/*.bin 2>/dev/null || true
            if ! ./rebuild_all.sh >"${CONFIG_BUILD_LOG}" 2>&1; then
                echo "  CONFIG BUILD FAIL — see ${CONFIG_BUILD_LOG} (tail):"
                tail -20 "${CONFIG_BUILD_LOG}" | sed 's/^/    /'
                echo "  Marking all ${SWEEP_REPS}×${#SWEEP_APPS} cells of this config as FAIL_BUILD."
                # Skip the whole config — log all its cells as FAIL_BUILD.
                for app in ${SWEEP_APPS}; do
                    for rep in $(seq 0 $((SWEEP_REPS - 1))); do
                        CELL_IDX=$((CELL_IDX + 1))
                        CELL_FAIL=$((CELL_FAIL + 1))
                    done
                done
                continue
            fi

            # Build the non-fib bench .bins for THIS config so flashing
            # later finds them. fib is bundled in tock.elf by
            # rebuild_all.sh; the rest need taclebench/Makefile.
            if [ -d "${TACLE_DIR}" ]; then
                echo "  -- build bench .bins (eval_apps)"
                if ! make -C "${TACLE_DIR}" eval_apps >>"${CONFIG_BUILD_LOG}" 2>&1; then
                    echo "  WARN — make eval_apps failed; non-fib cells will fail"
                    tail -20 "${CONFIG_BUILD_LOG}" | sed 's/^/    /'
                fi
            fi

            # Inner loop: app + rep, SWEEP_SKIP_BUILD=1 to reuse build.
            for app in ${SWEEP_APPS}; do
                for rep in $(seq 0 $((SWEEP_REPS - 1))); do
                    CELL_IDX=$((CELL_IDX + 1))
                    NOW=$(date +%s)
                    ELAPSED=$((NOW - START_EPOCH))
                    if [ ${CELL_IDX} -gt 0 ]; then
                        ETA_REMAINING=$(( (ELAPSED * (N_CELLS - CELL_IDX) ) / CELL_IDX ))
                    else
                        ETA_REMAINING=0
                    fi
                    printf "  [%4d/%-4d] %-14s rep=%d  (PASS=%d FAIL=%d SKIP=%d, elapsed=%ds, ETA=%ds)\n" \
                        ${CELL_IDX} ${N_CELLS} "${app}" ${rep} \
                        ${CELL_PASS} ${CELL_FAIL} ${CELL_SKIP} \
                        ${ELAPSED} ${ETA_REMAINING}

                    # Capture the EXIT code of run_eval_sweep.sh to
                    # classify the cell outcome. The sweep script is
                    # idempotent: if the CSV row exists, it exits 0
                    # immediately (we count that as SKIP).
                    SWEEP_CELL_OUT="${INVOCATION_DIR}/eval_logs/grid_cell_${app}_slot${slot}_cache${cache}_spec${spec}_rep${rep}.out"
                    set +e
                    SWEEP_SKIP_BUILD=1 \
                    SWEEP_APP="${app}" SWEEP_SLOT="${slot}" \
                    SWEEP_CACHE="${cache}" SWEEP_SPEC="${spec}" \
                    SWEEP_REP="${rep}" \
                        ./tools/run_eval_sweep.sh >"${SWEEP_CELL_OUT}" 2>&1
                    RC=$?
                    set -e

                    if [ ${RC} -eq 0 ]; then
                        if grep -q "^==> SKIP" "${SWEEP_CELL_OUT}"; then
                            CELL_SKIP=$((CELL_SKIP + 1))
                        else
                            CELL_PASS=$((CELL_PASS + 1))
                        fi
                    else
                        CELL_FAIL=$((CELL_FAIL + 1))
                    fi
                done
            done

            # Periodic summary at config boundary.
            echo "  CONFIG done — running totals: PASS=${CELL_PASS} FAIL=${CELL_FAIL} SKIP=${CELL_SKIP}"
        done
    done
done

# ── Final summary ─────────────────────────────────────────────────────
END_EPOCH=$(date +%s)
TOTAL_SECONDS=$((END_EPOCH - START_EPOCH))
echo
echo "════════════════════════════════════════════════════════════════"
echo "  GRID DONE"
echo "════════════════════════════════════════════════════════════════"
echo "  Total cells:  ${N_CELLS}"
echo "  PASS:         ${CELL_PASS}"
echo "  FAIL:         ${CELL_FAIL}"
echo "  SKIP:         ${CELL_SKIP}  (already in CSV before this run)"
echo "  Wall time:    ${TOTAL_SECONDS}s ($((TOTAL_SECONDS / 3600))h $(( (TOTAL_SECONDS % 3600) / 60 ))m)"
echo "  CSV:          ${INVOCATION_DIR}/eval_master.csv"
echo "════════════════════════════════════════════════════════════════"

if [ ${CELL_FAIL} -gt 0 ]; then
    exit 2
fi
