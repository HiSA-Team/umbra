#!/usr/bin/env python3
"""Flip one byte of the host ELF's `._enclave_code` section in-place.

Used by `tools/smoke_test_fault.sh` to produce a tampered enclave binary for
negative testing. STM32L5 with TZEN=1 refuses openocd's runtime flash
write algorithm, so we instead corrupt the ELF at build time and re-flash via
GDB; the kernel's chained-measurement finalizer must reject the resulting
image.

Usage: corrupt_enclave.py <elf_path> [section_offset]

`section_offset` defaults to 32 (the first ciphertext byte of block 0 under
the chained layout [Meta(32)|CT(256)]). The byte is XORed with 0xFF, so
repeated invocations cycle the value rather than stacking.
"""

import os
import subprocess
import sys
import tempfile

SECTION_NAME = "._enclave_code"


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(f"[corrupt_enclave] FAILED: {' '.join(cmd)}\n{result.stderr}")
        sys.exit(1)
    return result.stdout


def main():
    if len(sys.argv) < 2:
        print("Usage: corrupt_enclave.py <elf_path> [section_offset]", file=sys.stderr)
        sys.exit(2)

    elf_path = sys.argv[1]
    offset = int(sys.argv[2], 0) if len(sys.argv) > 2 else 32

    with tempfile.TemporaryDirectory() as tmp:
        section_bin = os.path.join(tmp, "section.bin")
        run(["arm-none-eabi-objcopy", "-O", "binary",
             f"--only-section={SECTION_NAME}", elf_path, section_bin])

        with open(section_bin, "rb") as f:
            data = bytearray(f.read())

        if offset >= len(data):
            sys.stderr.write(
                f"[corrupt_enclave] offset {offset} out of bounds "
                f"(section size {len(data)})\n")
            sys.exit(1)

        original = data[offset]
        data[offset] ^= 0xFF
        with open(section_bin, "wb") as f:
            f.write(data)

        run(["arm-none-eabi-objcopy",
             f"--update-section={SECTION_NAME}={section_bin}", elf_path])

    print(f"[corrupt_enclave] {SECTION_NAME}[{offset}]: "
          f"0x{original:02x} -> 0x{data[offset]:02x}")


if __name__ == "__main__":
    main()
