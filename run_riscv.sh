#!/usr/bin/env bash
# Build + run the Umbra RISC-V (RV32) monitor on the patched QEMU (SPMP-capable).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
QEMU="${QEMU:-$ROOT/tools/qemu-spmp/install/bin/qemu-system-riscv32}"
# SPMP-active: the M-mode monitor programs SPMP regions so the U-mode host and
# S-mode enclave coexist, with the host SPMP-fenced out of the enclave's memory.
CPU="${CPU:-rv32,spmp=true}"
BOOT="$ROOT/src/hardware/platform/riscv32/boot"
ELF="$ROOT/target/riscv32imac-unknown-none-elf/release/umbra-rv32"
# The U-mode bare-metal host is a SEPARATE image (Rust, host/riscv32/bare_metal),
# loaded by QEMU at 0x8010_0000 alongside the M-mode monitor.
HOST="$ROOT/host/riscv32/bare_metal"
HOST_ELF="$HOST/target/riscv32imac-unknown-none-elf/release/bare_metal"

PY="${PYTHON:-/opt/miniconda3/bin/python}"
# Rotate the master key with the shared tool (tools/gen_key.py): writes
# tools/master_key.bin (read by the signer below) + each platform's master_key.rs
# (compiled into the monitor). Run before the monitor build.
"$PY" "$ROOT/tools/gen_key.py"

( cd "$BOOT" && cargo build --release )
( cd "$HOST" && cargo build --release )
# Divide + protect the embedded enclave with the shared tool
UMBRA_CROSS="${CROSS:-riscv64-unknown-elf-}" UMBRA_CHAINED=1 UMBRA_ESS_MISS_RECOVERY=1 "$PY" \
    "$ROOT/tools/protect_enclave.py" "$HOST_ELF" _ "$ROOT/tools/master_key.bin"

exec "$QEMU" -machine virt -cpu "$CPU" -bios none -kernel "$ELF" \
     -device loader,file="$HOST_ELF" \
     -display none -serial stdio -monitor none
