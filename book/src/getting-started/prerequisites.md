# Prerequisites

## Rust Toolchain

Install Rust via rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Switch to the nightly toolchain and add the Cortex-M33 target:

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

| Tool | Purpose | Install |
|---|---|---|
| OpenOCD | On-chip debugger backend | `brew install openocd` / `apt install openocd` |
| STM32 Programmer CLI | Initial flash configuration and TrustZone enable | [STMicro website](https://www.st.com/en/development-tools/stm32cubeprog.html) |
| gdbgui (optional) | Web-based GDB frontend | `pip install gdbgui` |

## Verify Installation

Run `source settings.sh` from the project root. The script checks all dependencies and reports any missing tools.
