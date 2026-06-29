#!/bin/bash
set -eo pipefail

source ./settings.sh

# ── RISC-V RV32 (QEMU) launch path ─────────────────────────────────────────
# No ST-LINK / OpenOCD: QEMU IS the target. Load the M-mode monitor at RAM
# origin and the U-mode host image at 0x8010_0000, route the 16550 UART to
# stdio. Set QEMU_DEBUG=1 to halt for GDB (gdbstub on :1234):
#   QEMU_DEBUG=1 ./debug.sh   then:  ${GDB} -ex 'target remote :1234' <monitor.elf>
if [ "${MCU_VARIANT}" = "riscv32" ]; then
    MON_ELF="${ROOT_DIR}/target/${TARGET_ARCH}/release/${BOOT_BIN_NAME}"
    if [ ! -f "${MON_ELF}" ] || [ ! -f "${HOST_ELF}" ]; then
        echo -e "${FAILURE:-}[riscv32] Build artifacts missing — run ./rebuild_all.sh first${VANILLA:-}" >&2
        exit 1
    fi
    GDB_FLAGS=""
    if [ "${QEMU_DEBUG:-0}" = "1" ]; then
        GDB_FLAGS="-s -S"
        echo -e "${BOLD:-}[riscv32] QEMU halted for GDB on :1234 (target remote :1234)${VANILLA:-}"
    fi
    echo -e "${BOLD:-}[riscv32] Launching ${BOOT_BIN_NAME} + ${HOST_NAME} on QEMU (${QEMU_CPU})${VANILLA:-}"
    # virtio-mmio.force-legacy=false presents the modern (v2) transport on the
    # virt machine's 8 always-mapped virtio-mmio slots. Without it they default
    # to the legacy (v1) personality and the Tock S-guest panics in its VirtIO
    # transport ("Unknown VirtIO MMIO device version: 1"). Harmless for the
    # bare-metal host, which uses no virtio.
    exec "${QEMU}" -machine virt -cpu "${QEMU_CPU}" -bios none \
        -global virtio-mmio.force-legacy=false \
        -kernel "${MON_ELF}" -device loader,file="${HOST_ELF}" \
        -display none -serial stdio -monitor none ${GDB_FLAGS}
fi

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
# the full enclave scan range that the L5 bare_metal host iterates). The
# host's bundled fib enclave at 0x08078000 is overwritten by
# `make program_elf_host` below, so erasing sector 240 is safe.
#
# Gated on L552/L562 only; N657 uses XSPI-mapped flash at 0x70000000+
# with a completely different sector layout.
if [ "${MCU_VARIANT}" = "stm32l552" ]; then
    echo -e "${BOLD:-}Wiping NS-flash enclave scan range (sectors 240-255, per-sector)${VANILLA:-}"
    for sec in 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255; do
        "${FLASHER}" -c port="${PORT_NAME}" --erase "${sec}" "${sec}" \
            >/dev/null 2>&1 || echo "  (sector ${sec} skipped)"
    done
fi

# Spawn openocd between the STM32_Programmer_CLI wipe (releases ST-LINK)
# and the GDB-driven `program_elf_*` flash (needs openocd on :3333). Per
# memory `feedback_l562_flash_workflow.md`: don't delay between programmer
# release and openocd attach — L562 OCTOSPI clocks can drift otherwise.
# Same bounce pattern as tools/smoke_test_fault_runtime.sh.
pkill -x openocd 2>/dev/null || true
sleep 0.5
OOCD_LOG="${OOCD_LOG:-/tmp/umbra-openocd-${MCU_VARIANT}.log}"
echo -e "${BOLD:-}Starting openocd (log: ${OOCD_LOG})${VANILLA:-}"
"${OPENOCD}" -f "${OPENOCD_CONFIG}" >"${OOCD_LOG}" 2>&1 &
OOCD_PID=$!
# Tear down openocd only on script END (EXIT covers both normal end +
# bash exiting via signal) or explicit TERM. INT is *intentionally
# excluded*: when the user presses Ctrl+C during the interactive GDB
# session, they want to interrupt the running target on the chip — not
# kill the openocd backend GDB is talking to. GDB handles SIGINT
# internally (returns to prompt); leaving openocd alive keeps the
# debug session usable. openocd dies at the natural end of the script,
# when GDB has been quit cleanly.
trap 'kill ${OOCD_PID} 2>/dev/null; wait ${OOCD_PID} 2>/dev/null; true' EXIT TERM
# Wait up to 15s for openocd to claim port 3333.
for _ in $(seq 1 30); do
    if lsof -nP -iTCP:3333 -sTCP:LISTEN >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
if ! lsof -nP -iTCP:3333 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "ERROR: openocd did not come up on :3333 within 15s. Tail of ${OOCD_LOG}:" >&2
    tail -20 "${OOCD_LOG}" >&2 || true
    exit 1
fi

make program_elf_boot && make program_elf_host