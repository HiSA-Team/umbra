# Prerequisites

## Rust Toolchain

Install Rust via rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Switch to the nightly toolchain and add the Armv8-M mainline target. The
same target serves both Cortex-M33 (STM32L5) and Cortex-M55 (STM32N6) —
the M55 runs in the M33-compatible subset; MVE/Helium and the
double-precision FPU are not used in the kernel.

```bash
rustup toolchain install nightly
rustup override set nightly
rustup target add thumbv8m.main-none-eabi
```

## ARM Cross-Compiler

Install the ARM bare-metal toolchain. The following tools are required:

| Tool | Purpose |
|---|---|
| `arm-none-eabi-gcc` | C cross-compiler (for host application) |
| `arm-none-eabi-ld` | Linker |
| `arm-none-eabi-objcopy` | Binary conversion (ELF to BIN) |
| `arm-none-eabi-objdump` | Disassembly and section inspection |
| `arm-none-eabi-gdb` | Debugger |

On macOS (Homebrew):
```bash
brew install --cask gcc-arm-embedded
```

On Ubuntu/Debian:
```bash
sudo apt install gcc-arm-none-eabi
```

## Debug and Flash Tools

| Tool | Purpose | Required for | Install |
|---|---|---|---|
| OpenOCD | On-chip debugger backend | STM32L5 (GDB load), N657 GDB attach | `brew install openocd` / `apt install openocd` |
| STM32CubeProgrammer | Option bytes, external loaders, FSBL signing | **All targets** | [STMicro website](https://www.st.com/en/development-tools/stm32cubeprog.html) |
| `STM32_SigningTool_CLI` | Sign the FSBL image for Boot ROM | STM32N6 only | Bundled with STM32CubeProgrammer |
| ST Edge AI | Regenerate NPU bytecode from `.onnx` | N657 NPU demo only | [STMicro website](https://www.st.com/en/development-tools/stedgeai-core.html) |
| gdbgui (optional) | Web-based GDB frontend | optional | `pip install gdbgui` |

### STM32CubeProgrammer paths

`tools/flash_n657.sh` (and the L562 `program_enclaves_extload` target)
locate the signing tool, programmer CLI, and external loaders via the
default macOS install path. Override on Linux:

```bash
export STM32CUBE_PROG_DIR=/opt/st/stm32cubeprog/bin
```

Individual tools can also be overridden with `STM32_SIGNING_TOOL`,
`STM32_PROGRAMMER`, and `STM32_EXT_LOADER_N657`.

## Verify Installation

Run `source settings.sh` from the project root. The script checks all
dependencies, reports any missing tools, and configures paths, flash
addresses, and feature flags for the MCU selected via `MCU_VARIANT`.
