#!/usr/bin/env bash
# Build + run the S-mode SPMP CSR liveness spike on the patched QEMU.
# Expected stdout: "SPMP cfg0 readback nibble=0x<nonzero>"
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GCC="${GCC:-/opt/homebrew/bin/riscv64-unknown-elf-gcc}"
QEMU="${QEMU:-$HERE/../install/bin/qemu-system-riscv32}"

"$GCC" -march=rv32imac_zicsr -mabi=ilp32 -nostdlib -nostartfiles -ffreestanding \
       -T "$HERE/link.ld" "$HERE/spmp_smoketest.S" -o "$HERE/spmp_smoketest.elf"

exec "$QEMU" -machine virt -cpu rv32,spmp=true -bios none \
     -kernel "$HERE/spmp_smoketest.elf" -display none -serial stdio -monitor none
