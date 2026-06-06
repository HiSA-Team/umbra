#!/usr/bin/env bash
# tools/check_file_size.sh — enforce per-file LOC caps.
#
# Hard cap: 600 LOC. Files above this CAUSE CI failure.
# Soft cap: 400 LOC. Files above this PRINT WARNING but allow CI to pass.
#
# Excludes: vendored deps (lib/), host apps (host/), tools/, target/,
# generated bootstrap stubs (master_key.rs / boot_measurements.rs).

set -euo pipefail

HARD_CAP=600
SOFT_CAP=400

EXIT_CODE=0

# macOS ships bash 3.2 (no `mapfile`), so use a pipe-friendly loop.
# The redirect at the bottom feeds the loop in the current shell so
# `EXIT_CODE` modifications survive after `done`.
while IFS= read -r f; do
    lines=$(wc -l < "$f")
    if [ "$lines" -gt "$HARD_CAP" ]; then
        echo "HARD-CAP VIOLATION (${lines} LOC > ${HARD_CAP}): ${f}" >&2
        EXIT_CODE=1
    elif [ "$lines" -gt "$SOFT_CAP" ]; then
        echo "SOFT WARNING (${lines} LOC > ${SOFT_CAP}): ${f}" >&2
    fi
done < <(find src crates -name '*.rs' \
    -not -path '*/target/*' \
    -not -name 'master_key.rs' \
    -not -name 'boot_measurements.rs' \
    | sort)

if [ "$EXIT_CODE" -ne 0 ]; then
    echo >&2
    echo "Decompose the offending file(s) or add a hard-cap waiver in this script with rationale." >&2
    exit "$EXIT_CODE"
fi

echo "All Rust source files within size caps (hard=${HARD_CAP}, soft=${SOFT_CAP})."
