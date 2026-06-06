#!/bin/bash
set -eo pipefail

source ./settings.sh
export UMBRA_ESS_MISS_RECOVERY=1

# Secure boot kernel build.
make secureboot_clean
make secureboot_build

# Umbra library build.
make umbra_clean
make umbra_build

# Host (NS) build.
cd "${HOST_DIR}"
make clean
make
cd "${ROOT_DIR}"

# Re-sign all standalone TACLeBench enclave blobs against the freshly-built
# master_key.bin. Without this, blobs from previous sessions (still on disk
# as host/stm32l552/taclebench/app/*.bin) stay signed against the OLD key.
# When the user re-flashes one of them to a 4 KB-aligned NS-flash sector,
# the secure boot rejects it with `chained-measurement FAIL`. Option B of
# the rebuild story: keep all known enclaves consistent with the current key.
#
# `make all` (host/stm32l552/taclebench/Makefile) iterates the validated
# benchmarks and re-runs protect_enclave.py for each → fresh HMAC +
# chained-measurement baked into the header. complex_updates is
# intentionally excluded (needs float-emulation routines from libgcc which
# `-nostdlib` rejects).
#
# Gated on L552/L562 because taclebench targets that architecture only.
if [ "${MCU_VARIANT}" = "stm32l552" ]; then
    if [ -d "${ROOT_DIR}/host/stm32l552/taclebench" ]; then
        echo -e "${BOLD}Re-signing TACLeBench enclave blobs${VANILLA:-}"
        make -C "${ROOT_DIR}/host/stm32l552/taclebench" clean all
    fi
fi
