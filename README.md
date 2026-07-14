<p align="center">
  <img src="assets/logo.svg" width="400" alt="Umbra Logo">
</p>

<p align="center">
  <a href="https://github.com/HiSA-Team/umbra/actions/workflows/build.yml"><img src="https://github.com/HiSA-Team/umbra/actions/workflows/build.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/HiSA-Team/umbra"><img src="https://codecov.io/gh/HiSA-Team/umbra/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/HiSA-Team/umbra/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-nightly-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/platform-STM32L5%20%7C%20STM32N6%20%7C%20RISC--V-green.svg" alt="Platform">
  <a href="https://hisa-team.github.io/umbra/"><img src="https://img.shields.io/badge/docs-mdBook-blue.svg" alt="Documentation"></a>
</p>

# Umbra: creating rust-based TEEs on Arm TrustZone-M

Umbra is a lightweight Rust-based kernel designed to wrap binaries into runtime Trusted Execution Environments (TEEs) for TrustZone-M.
It is distributed as a static library, enabling integration with third-party software such as RTOSes or bare-metal applications to create TEEs dynamically or statically.
By leveraging Rust, Umbra minimizes the Trusted Computing Base (TCB) and enhances code safety.

Currently supported targets:

| Board | MCU | Core | Notable |
|---|---|---|---|
| NUCLEO-L552ZE-Q | STM32L552 | Cortex-M33 | Software AES, DMA block loading |
| STM32L562E-DK | STM32L562 | Cortex-M33 | Hardware AES, OCTOSPI + OTFDEC |
| NUCLEO-N657X0-Q | STM32N657 | Cortex-M55 | FSBL boot from XSPI2, HW SHA-256 + AES-CTR (DMA-fed via HPDMA1), NPU-in-enclave demo |
| QEMU `virt` (RV32) | RISC-V RV32 (M/S/U) | rv32imac | EFB block demand-paging, SW AES-128-CTR + SHA-256, PMP/SPMP isolation, ePMP `.text` self-lock — hardware-free (QEMU) |

> **Trust model note.** The STM32 targets derive their guarantees from a silicon
> root of trust. The RISC-V target runs on an **SPMP-patched** `qemu-system-riscv32`
> (SPMP is not yet upstream) and has **no hardware root of trust / attestation** —
> it is a fully-open, reproducible reference/emulation target for the isolation
> model (PMP/SPMP/ePMP), not a silicon-equivalent secure deployment.

## Architecture

Umbra is organised as a Cargo workspace with a leaf-crate dependency tree:

```
umbra-error  <-  umbra-hal  <-  umbra-api  <-  umbra-kernel  <-  per-platform PAL crates
                                            ^
                                       umbra-pal-test (host-side testing)
```

- **`crates/umbra-api`** — leaf crate. Holds `Platform`, `CryptoEngine`, and the
  `SecurityState` markers (`Validated`/`Loaded`/`Executing`) that make enclave
  misuse a compile error via `EnclaveHandle<S>`.
- **`crates/umbra-hal`** — HAL traits (`Hash`, `Aes`, `Dma`, `Rcc`, `Uart`, `Gpio`).
  Per-platform impls live in PAL crates.
- **`crates/umbra-error`** — `UmbraError` enum + `UmbraResult<T>` alias; replaces
  the pre-refactor `Result<T, ()>` pattern.
- **`crates/umbra-pal-test`** — host-side test platform (MmioMem + TestPlatform) for
  kernel and driver unit tests.
- **`src/kernel/`** — `umbra-kernel` Secure-side kernel (no_std).
- **`src/hardware/platform/stm32{l552,l562,n657}/{boot,drivers}/`** —
  per-platform PAL crates (`umbra-l552-boot`, `umbra-l552-drivers`,
  `umbra-n657-boot`, `umbra-n657-drivers`).
- **`src/hardware/architecture/riscv/`** (`umbra-riscv-arch`) +
  **`src/hardware/platform/riscv32/boot/`** (`umbra-riscv32-boot`) — the RISC-V
  RV32 arch layer (PMP/SPMP/CSR/trap policy, host-tested) and M-mode monitor.
- **`xtask/`** — Rust build/flash/test orchestration; entry-point for `cargo xtask`.

Operational rules, threat-model invariants, panic policy, and the
reviewer checklist live in the mdBook (`book/`) and are published at
[hisa-team.github.io/umbra](https://hisa-team.github.io/umbra/).

## STM32N6 root of trust

On STM32N6, Umbra runs as the signed First-Stage Boot Loader (FSBL) and
hardens the root of trust with increments that stay reversible on the
BSEC-open development board (no OTP fuse is burned, debug stays enabled):

- **HDPL temporal isolation** — the FSBL raises the Hide-Protection Level
  before the Non-Secure handoff, so the hardware-unique key it derived is
  not recoverable by later stages.
- **DHUK key delivery** — the enclave AES key is wrapped under the device
  Derived Hardware-Unique Key and shared to the `CRYP` engine over the
  on-chip `SAES → CRYP` key bus, so it never sits in CPU-readable memory.
- **Dual-FSBL fail-safe** — two FSBL copies at the Boot-ROM offsets; a
  structurally-bad image 1 falls back to image 2 (demonstrated on hardware).
- **ECDSA-P256 signing** — the FSBL is emitted as a signed STM32 v2.3 image
  with an anti-rollback version field.
- **Enclave ↔ FSBL version binding** — the enclave measurement is seeded
  with a build epoch, so an enclave runs only under the FSBL it was built
  for.

Signature and confidentiality *enforcement* require the irreversible OTP
`secure_boot` close (out of scope for the open dev board); see the
[STM32N657 hardware page](https://hisa-team.github.io/umbra/hardware/stm32n657.html)
for the full rationale and the open-board-vs-post-close split.

## Install Dependencies
To build Umbra, rust is required
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Currently, we are using nightly instead of stable.
Therefore users are required to
```
rustup toolchain install nightly
rustup override set nightly
```
Finally add the Armv8-M mainline target (covers both Cortex-M33 and Cortex-M55):
```
rustup target add thumbv8m.main-none-eabi
```
For the RISC-V RV32 (QEMU `virt`) target, add its triple instead:
```
rustup target add riscv32imac-unknown-none-elf
```
The RISC-V flow needs the `riscv64-unknown-elf-` GCC toolchain (the signer only
uses its `objcopy`/`objdump`) and the SPMP-patched `qemu-system-riscv32`, built
once from the `tools/qemu-spmp` submodule via
`tools/qemu-spmp/build-qemu-spmp.sh`. **No hardware required.**

Additional tools required for building and running:
- **ARM toolchain** (`gcc-arm-none-eabi`) — C cross-compiler, linker, objcopy, gdb.
- **OpenOCD** — used together with GDB to load ELFs over SWD on STM32L5.
- **STM32CubeProgrammer** ([download](https://www.st.com/en/development-tools/stm32cubeprog.html))
  — required on all targets for option-byte programming.
  On **STM32L562** it programs the plaintext enclave to OCTOSPI via the
  `MX25LM51245G_STM32L562E-DK.stldr` external loader.
  On **STM32N657** the bundled `STM32_SigningTool_CLI` signs the FSBL and
  `STM32_Programmer_CLI` flashes it (plus host bin and NPU artifacts) to
  XSPI2 via the `MX25UM51245G_STM32N6570-NUCLEO.stldr` external loader.
- **ST Edge AI** (NPU demo only) — required to regenerate the Tiny YOLO v2
  bytecode. See [`book/src/examples/object-detection.md`](book/src/examples/object-detection.md).

## Build

### `cargo xtask` (canonical)

```
cargo xtask build l552    # STM32L552 (Cortex-M33, SW AES)
cargo xtask build l562    # STM32L562 (HW AES + OTFDEC)
cargo xtask build n657    # STM32N657 (Cortex-M55, HW CRYP1)
cargo xtask build riscv32 # RISC-V RV32 (QEMU virt, M/S/U)
cargo xtask test --host   # host-side tests + coverage
cargo xtask check-binary-size <platform>
```

Run `cargo xtask --help` for the full entry-point list.

### Shell-script flow (still supported)

Pick the target MCU in [`settings.sh`](settings.sh) by setting `MCU_VARIANT`
to one of `stm32l552`, `stm32l562`, `stm32n657`, or `riscv32`, then source the
script:
```
source settings.sh
```
Optionally pick a non-default host application (`bare_metal` is the default;
other options vary per MCU):
```
export HOST_APP=freertos         # STM32L5 + STM32N6
export HOST_APP=tock             # STM32L552 only
export HOST_APP=object_detection # STM32N6 only
source settings.sh
```
Then full-rebuild everything (Secure boot, kernel staticlib, host bin,
enclave protection step):
```
./rebuild_all.sh
```

## Flash and Run

### STM32L5 (L552, L562)

```
cargo xtask flash l552    # or l562
```

Equivalent shell-script flow: `./debug.sh` (with OpenOCD already running). On
L562, both paths also program the plaintext enclave blob to OCTOSPI via
STM32CubeProgrammer.

### STM32N6 (N657)

The N6 has no internal flash. The Boot ROM loads a signed FSBL image
from XSPI2 into AXISRAM2 on each reset:

```
cargo xtask flash n657    # signs FSBL + flashes via STM32_Programmer_CLI
```

Equivalent shell entry-point: `tools/flash_n657.sh`. The script signs the
FSBL with `STM32_SigningTool_CLI` and writes FSBL + host bin (+ NPU bytecode
and weights for the object-detection demo) to XSPI2 with `STM32_Programmer_CLI`.
Set the board's JP2 (BOOT1) jumper to *Flash Boot* and reset — UART comes up
at **115200 baud** (vs **9600 baud** on STM32L5).

Override the tool install dir for non-macOS hosts:
```
export STM32CUBE_PROG_DIR=/opt/st/stm32cubeprog/bin
```

### RISC-V RV32 (QEMU `virt`)

No hardware or flashing — the monitor + host run on the SPMP-patched
`qemu-system-riscv32`:

```
cargo xtask flash riscv32   # build + run on the SPMP-patched QEMU
```

Equivalent shell-script flow: `MCU_VARIANT=riscv32 ./debug.sh` launches QEMU
(set `QEMU_DEBUG=1` to expose a gdbstub on `:1234`). A successful run ends with
the enclave result on the UART: `[USER] Enclave terminated! R0=0x72CA33A8`.

## Documentation

A full mdBook lives under [`book/`](book/) and is published to
[hisa-team.github.io/umbra](https://hisa-team.github.io/umbra/). Build it
locally with `mdbook serve book` after `cargo install mdbook`.

Topics covered:
- Architecture (Cargo workspace, HAL traits, type-state security domain,
  `UmbraError`, Secure boot, ESS demand-paged enclave cache, NSC veneers)
- FSBL boot model for STM32N6 (Boot ROM, signing, AXISRAM layout)
- Per-board hardware setup (L552, L562, N657)
- Host examples (bare-metal, FreeRTOS, Tock, NPU object detection)
- Formal verification of the integrity model (ProVerif)
- **Porting to a new board** — step-by-step using the `PlatformBoot` trait
  (now in `crates/umbra-api`, implemented by each `umbra-<mcu>-boot` crate)

## Contributing

The mdBook (`book/`, published to
[hisa-team.github.io/umbra](https://hisa-team.github.io/umbra/)) has
chapters on the workspace layout, the HAL trait surface, the
type-state security domain, error handling, the `umbra-api` leaf
crate, boot flow, the ESS demand-paged enclave cache, NSC veneers,
the threat model + panic policy, the porting guide, and the
contributor guardrails (NEVER_DO / ALWAYS_DO / code-review checklist).
Start at [Crate Structure](book/src/architecture/crate-structure.md)
or the published index.
