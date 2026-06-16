# QEMU with RISC-V SPMP (Smspmp) support

Umbra's RISC-V S-mode enclave port (issue #57) needs `qemu-system-riscv32`
with **SPMP** (S-mode Physical Memory Protection). SPMP is **not in upstream
QEMU** — it exists only as an RFC patchset. This directory pins upstream QEMU
as a submodule and rebuilds it with the patches applied.

## Layout

| Path | Tracked? | What |
|------|----------|------|
| `qemu/` | submodule (gitlink) | upstream QEMU pinned at `QEMU_PIN` |
| `QEMU_PIN` | yes | the upstream commit the patches apply to |
| `patches/0001..0006` | yes | the 6 SPMP RFC patches (`git am` format) |
| `build-qemu-spmp.sh` | yes | checkout pin → apply patches → build |
| `smoketest/` | yes (source only) | S-mode SPMP CSR liveness check |
| `install/` | git-ignored | the built `qemu-system-riscv32` |

`qemu/` is a **submodule**, not a copy — the superproject stores only a pointer
(SHA `48221e37`), so there is no repo bloat. The patches are applied on top at
build time; the submodule pointer stays at the clean upstream commit.

## Provenance

- Series: `[RFC PATCH 0/6] ... SPMP` by Luis Cunha, qemu-devel, 2026-03-18.
- Patchew: <https://patchew.org/QEMU/20260318185238.99143-1-luisccunha8@gmail.com/>
- Message-id: `20260318185238.99143-1-luisccunha8@gmail.com`
- SPMP spec: v0.9.8 (in development). Adds `target/riscv/spmp.{c,h}`, CPU
  properties `spmp=true` + `sspmpen=true`.
- `QEMU_PIN` = `48221e371686f7704f150aafe46b76bb9306c7b6` (upstream master tip
  2026-03-16, ~`v11.0.0-rc0~8`; the patches `git am` cleanly here).

## Reproduce (from a fresh clone)

```bash
# 1. fetch the QEMU submodule at the pinned commit
git submodule update --init tools/qemu-spmp/qemu

# 2. build qemu-system-riscv32 with the SPMP patches applied
#    Linux:  PYTHON=python3 ./tools/qemu-spmp/build-qemu-spmp.sh
#    macOS:  PYTHON=/opt/miniconda3/bin/python3.12 ./tools/qemu-spmp/build-qemu-spmp.sh
cd tools/qemu-spmp && PYTHON=/opt/miniconda3/bin/python3.12 ./build-qemu-spmp.sh

# 3. sanity: spmp must be a real CPU property
./install/bin/qemu-system-riscv32 -machine virt -cpu rv32,spmp=true -bios none -S
#    (must NOT print "Property 'spmp' not found")

# 4. S-mode SPMP CSR liveness smoketest
GCC=/opt/homebrew/bin/riscv64-unknown-elf-gcc ./smoketest/run.sh
#    expected: "SPMP cfg[0] readback nibble=0xF"
```

Build deps — Linux: `git build-essential ninja-build meson python3 python3-venv
python3-pip pkg-config libglib2.0-dev libpixman-1-dev zlib1g-dev flex bison`
plus `gcc-riscv64-unknown-elf`. macOS: `brew install glib pkg-config ninja
pixman dtc` plus a Python ≥3.11 (conda 3.12 verified) and the riscv ELF GCC.

## Verification status (2026-06-07) — ✅ FULL GATE PASS

- ✅ Patches `git am` cleanly onto the pin: 6/6, zero rejects.
- ✅ Builds — native macOS, conda Python 3.12 → `qemu-system-riscv32` 10.2.50.
- ✅ `-cpu rv32,spmp=true` accepted (errors on stock QEMU).
- ✅ S-mode SPMP CSRs live — smoketest prints `SPMP cfg[0] readback nibble=0xF`.

### Gotcha (cost two build cycles — DO NOT repeat)

QEMU's source tree contains a **tracked** `pyvenv/` directory (holding
`pyvenv/meson.build`, referenced by `subdir('pyvenv')` in the top `meson.build`).
It collides by NAME with the build-time venv at `build/pyvenv`. Running
`rm -rf pyvenv` in the **source** root deletes the tracked `pyvenv/meson.build`,
after which every configure fails `Nonexistent build file 'pyvenv/meson.build'`
— on macOS AND Linux. Fix: `git -C qemu checkout -- pyvenv/meson.build`. The
build script only ever `rm -rf build` (never `pyvenv`).

### SPMP programming model (important — for the Umbra port)

SPMP registers are **indirect CSRs (Sscsrind)**, not direct `spmpcfg0`/
`spmpaddr0`:
- `siselect (0x150) = 0x100 + entry_index`  (`ISELECT_SPMP_BASE = 0x100`)
- `sireg  (0x151)` ↔ `spmpaddr[index]`
- `sireg2 (0x152)` ↔ `spmpcfg[index]`
- Gating: at reset `mpmpdeleg = 64` ⇒ no SPMP rules delegated to S. M-mode must
  write `mpmpdeleg (0x316)` to `1..=63` first (`num_deleg_rules = 64 - mpmpdeleg`).
- Use numeric CSR literals — binutils lacks the non-ratified SPMP CSR names.
