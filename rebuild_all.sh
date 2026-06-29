#!/bin/bash
set -eo pipefail

source ./settings.sh
export UMBRA_ESS_MISS_RECOVERY=1

# ── RISC-V RV32 (QEMU) build path ──────────────────────────────────────────
# The RISC-V monitor + host are Cargo crates. Generate the master key, build the
# M-mode monitor and the U-mode bare-metal host, then divide + protect the
# embedded enclave (EFB 320-byte blocks: AES-128-CTR encrypt + per-block HMAC +
# chained measurement) with the SAME tool the STM32 platforms use —
# tools/protect_enclave.py with the RISC-V toolchain prefix. The monitor
# demand-loads + verifies + decrypts blocks at runtime.
if [ "${MCU_VARIANT}" = "riscv32" ]; then
    # Rotate the master key with gen_key.py
    # writes tools/master_key.bin (read by the signer below) AND each platform's
    # master_key.rs (compiled into the monitor). Run BEFORE the monitor build so
    # crypto_impl::MASTER_KEY picks up the fresh key.
    # Both the bare-metal host and the Tock host (sub-slice 3d) embed an enclave
    # and are signed with this key, so the key must match the monitor's. (Revert
    # master_key.rs + master_key.bin via git checkout after the build.)
    echo -e "${BOLD:-}[riscv32] Generating master key (tools/gen_key.py)${VANILLA:-}"
    "${PYTHON}" "${ROOT_DIR}/tools/gen_key.py"
    echo -e "${BOLD:-}[riscv32] Building M-mode monitor (${BOOT_CRATE_NAME})${VANILLA:-}"
    ( cd "${SECBOOT_DIR}" && ${CARGO} build --release )
    echo -e "${BOLD:-}[riscv32] Building S-mode host (${HOST_NAME})${VANILLA:-}"
    ( cd "${HOST_DIR}" && ${CARGO} build --release ${HOST_FEATURES:+--features "$HOST_FEATURES"} )
    # Divide + protect the embedded enclave (EFB 320-byte blocks: AES-128-CTR +
    # per-block HMAC + chained measurement). For HOST_APP=tock, HOST_ELF is the
    # relinked Tock board, which embeds the enclave at _enclave_start (layout.ld).
    echo -e "${BOLD:-}[riscv32] Protecting embedded enclave (EFB block division + chained measurement)${VANILLA:-}"
    UMBRA_CROSS="${GCC_PREFIX}" UMBRA_CHAINED=1 UMBRA_ESS_MISS_RECOVERY=1 \
        "${PYTHON}" "${ROOT_DIR}/tools/protect_enclave.py" \
        "${HOST_ELF}" _ "${ROOT_DIR}/tools/master_key.bin"
    echo -e "${SUCCESS:-}[riscv32] Build complete. Launch with ./debug.sh${VANILLA:-}"
    exit 0
fi

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
