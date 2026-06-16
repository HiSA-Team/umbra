#!/usr/bin/env bash
# Build qemu-system-riscv32 with the SPMP RFC patchset applied.
#
# QEMU is a git SUBMODULE at tools/qemu-spmp/qemu, pinned to the upstream
# commit in QEMU_PIN (48221e37). The 6 RFC patches in patches/ apply CLEANLY
# on top of that pin (verified 2026-06-07, `git am` 6/6, zero rejects) and are
# applied here at build time — the submodule pointer stays at the clean
# upstream commit; the patches live as files in this repo.
#
# This script leaves the submodule working tree DIRTY (6 patch commits ahead of
# the pin). That is expected. To reset: `git -C qemu checkout -f $(cat QEMU_PIN)`.
#
# macOS note: pass a Python >= 3.11 that has venv/ensurepip. The system/brew
# Python works; conda also works:
#   PYTHON=/opt/miniconda3/bin/python3.12 ./build-qemu-spmp.sh
# Verified working: native macOS + conda Python 3.12 -> qemu 10.2.50.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/qemu"
PIN="$(cat "$HERE/QEMU_PIN")"
PREFIX="${QEMU_PREFIX:-$HERE/install}"
PYTHON="${PYTHON:-python3}"

# Ensure the submodule is checked out (no-op if already initialized).
if [ ! -f "$SRC/configure" ]; then
  git -C "$HERE/../.." submodule update --init tools/qemu-spmp/qemu
fi

# Reset to the clean pin, then apply our patches on top.
# `git am` records a committer, so it needs an identity — a clean CI runner has
# none ("fatal: empty ident name"). Provide one inline so the build works in any
# environment (a developer's global git identity is harmlessly overridden here).
GIT_AM=(git -C "$SRC" -c user.name="umbra-ci" -c user.email="umbra-ci@localhost")
"${GIT_AM[@]}" am --abort 2>/dev/null || true
git -C "$SRC" checkout -f "$PIN"
"${GIT_AM[@]}" am "$HERE"/patches/000[1-6]

rm -rf "$SRC/build"   # ONLY build/ — never `pyvenv/` (a TRACKED source dir;
                      # deleting pyvenv/meson.build breaks every configure).
mkdir -p "$SRC/build"
( cd "$SRC/build" && ../configure --python="$PYTHON" \
    --target-list=riscv32-softmmu --prefix="$PREFIX" \
    --disable-docs --disable-werror )
make -C "$SRC/build" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
make -C "$SRC/build" install
echo "Built: $PREFIX/bin/qemu-system-riscv32"
echo "Verify: $PREFIX/bin/qemu-system-riscv32 -machine virt -cpu rv32,spmp=true -bios none -S"
