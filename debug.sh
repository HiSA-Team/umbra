#!/bin/bash
set -eo pipefail

source ./settings.sh

if [ "$MCU_VARIANT" = "stm32l562" ]; then
    # Flash the plaintext enclave blob into OCTOSPI.
    # The L562 target uses the HAL target-as-oracle cipher pass
    # (OTFDEC ENC-mode + OCTOSPI PP) to overwrite it with the real
    # ciphertext in place on first boot. There is no offline encryptor.
    make program_enclaves_extload
fi

# Wipe NS-flash (bank 2) BEFORE re-flashing the host. This clears any
# stale taclebench blobs left over from previous test sessions (signed
# against an older master_key.bin, which rebuild_all.sh rotates every
# run). Without the wipe, the kernel's `chained-measurement FAIL` line
# reappears on every boot for any leftover blob — confusing the trace
# and leaking ESS allocator slots inside the create path.
#
# We use the explicit per-sector loop form rather than `--erase 240 254`
# because STM32_Programmer_CLI v2.19 on dual-bank L552 (DBANK=1) has
# been observed to skip a multi-sector range and report "Protected
# sectors are not erased" even when no WRP/SECWM watermark covers them.
# The single-sector form (`--erase N N`) is the same one the user runs
# manually for individual blobs and is known to work reliably.
#
# Sectors 240-255 = 0x08078000..0x0807FFFF (16 × 2 KB pages = 32 KB,
# the full enclave scan range that bare_metal_arm host iterates). The
# host's bundled fib enclave at 0x08078000 is overwritten by
# `make program_elf_host` below, so erasing sector 240 is safe.
#
# Gated on L552/L562 only; N657 uses XSPI-mapped flash at 0x70000000+
# with a completely different sector layout.
if [ "${MCU_VARIANT}" = "stm32l552" ] || [ "${MCU_VARIANT}" = "stm32l562" ]; then
    echo -e "${BOLD:-}Wiping NS-flash enclave scan range (sectors 240-255, per-sector)${VANILLA:-}"
    for sec in 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255; do
        "${FLASHER}" -c port="${PORT_NAME}" --erase "${sec}" "${sec}" \
            >/dev/null 2>&1 || echo "  (sector ${sec} skipped)"
    done
fi

make program_elf_boot && make program_elf_host