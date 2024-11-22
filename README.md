# Umbra: creating rust-based TEEs on Arm TrustZone-M

Umbra is a lightweight Rust-based kernel designed to wrap binaries into runtime Trusted Execution Environments (TEEs) for TrustZone-M.
It provides APIs compliant with the TCG specification as a static library, enabling integration with third-party software such as RTOSes or bare-metal applications to create TEEs dynamically or statically.
By leveraging Rust, Umbra minimizes the Trusted Computing Base (TCB) and enhances code safety.
Currently, it supports Cortex-M33-based systems, including ST L552 and L562 microcontrollers.

// Install dependencies
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
Finally add the Armv8-M mainline target
```
rustup target add thumbv8m.main-none-eabi
```
Additional tools required for building and running include the ARM cross-compiler toolchain gcc-arm-none-eabi and the OpenOCD backend.
While GDB is used to load the ELF file, the initial flashing configuration for STM32 devices is performed using the STM32 Programmer tool.
- [ARM toolchain]():
- [OpenOCD](): 
- [STM32 Programmer Tool](https://github.com/STMicroelectronics/STM32PRGFW-UTIL):

## Build

Configure all the environmental variables
```
source  settings.sh
```
Build the secure boot ELF
```
make secureboot_build
```
Build the umbra library
```
Make umbra_build
```

## Usage

The static library will be available after build in `lib`. In order for an application to use umbra, the secure boot must be loaded first on the device.
This can be achieved by flashing the binary beforehand, or by using a loader. It is possible to use GDB (ensure to have a backend opened)
```
make program_elf_boot
```
an application must include the `lib/libumbra.a` and using the umbra-defined linker script files.
An example of it is included in `host/bare_metal_arm`. Once the example is compiled,
you can run
```
make program_elf_host
```