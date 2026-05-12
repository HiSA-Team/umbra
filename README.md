<p align="center">
  <img src="assets/logo.svg" width="400" alt="Umbra Logo">
</p>

<p align="center">
  <a href="https://github.com/HiSA-Team/umbra/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-nightly-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/platform-STM32L5%20%7C%20STM32N6-green.svg" alt="Platform">
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
| NUCLEO-N657X0-Q | STM32N657 | Cortex-M55 | FSBL boot from XSPI2, HW HMAC-SHA256, NPU-in-enclave demo |

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

Pick the target MCU in [`settings.sh`](settings.sh) by setting `MCU_VARIANT`
to one of `stm32l552`, `stm32l562`, or `stm32n657`, then source the script:
```
source settings.sh
```
Optionally pick a non-default host application (only `bare_metal` is the
default; the other options vary per MCU — see the table below):
```
export HOST_APP=freertos        # STM32L5 + STM32N6
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

OpenOCD must be running; then GDB loads both ELFs:
```
./debug.sh
```
On L562, `debug.sh` also programs the plaintext enclave blob to OCTOSPI
via STM32CubeProgrammer.

### STM32N6 (N657)

The N6 has no internal flash. The Boot ROM loads a signed FSBL image
from XSPI2 into AXISRAM2 on each reset. To flash:

```
tools/flash_n657.sh
```

It signs the FSBL with `STM32_SigningTool_CLI` and writes FSBL + host bin
(+ NPU bytecode and weights for the object-detection demo) to XSPI2 with
`STM32_Programmer_CLI`. Set the board's JP2 (BOOT1) jumper to *Flash
Boot* and reset — UART comes up at **115200 baud** (vs **9600 baud** on
STM32L5).

Override the tool install dir for non-macOS hosts:
```
export STM32CUBE_PROG_DIR=/opt/st/stm32cubeprog/bin
```

## Documentation

A full mdBook lives under [`book/`](book/) and is published to
[hisa-team.github.io/umbra](https://hisa-team.github.io/umbra/). Build it
locally with `mdbook serve book` after `cargo install mdbook`.

Topics covered:
- Architecture (Secure boot, ESS demand-paged enclave cache, NSC veneers)
- FSBL boot model for STM32N6 (Boot ROM, signing, AXISRAM layout)
- Per-board hardware setup (L552, L562, N657)
- Host examples (bare-metal, FreeRTOS, NPU object detection)
- Formal verification of the integrity model (ProVerif)
- **Porting to a new board** — step-by-step using the `PlatformBoot` trait
