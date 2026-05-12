# Porting to a New Board

This chapter walks through the work needed to add support for a new
microcontroller. It is based on the STM32L552 → STM32N657 port (issue
#38) and reflects the bring-up landmines that port actually hit.

The goal is not to enumerate every difference — that's the job of the
reference manual — but to make it clear *which files to touch, in what
order*, and *which assumptions in the existing kernel will or won't
travel*.

## Prerequisites

- A TrustZone-M capable Cortex-M (M23, M33, M35P, or M55).
- A working toolchain for the target (`rustc`'s
  `thumbv8m.main-none-eabi` covers M33/M55 in the non-MVE subset; M23
  would need `thumbv8m.base-none-eabi`).
- A way to flash and authenticate code on the part — either internal
  flash with option-byte TZEN (like STM32L5) or an FSBL flow with a
  Boot ROM (like STM32N6).

## Step 0 — Answer the architecture questions first

Before writing any code, settle these eight questions. Each one shaped
a different part of the N657 port and getting any of them wrong wastes
days.

| # | Question | Why it matters |
|---|---|---|
| 1 | Where does the Secure boot live? Internal flash, or FSBL loaded by a Boot ROM? | Determines reset vector, linker `ORIGIN`, signing requirements |
| 2 | What is the IDAU aliasing scheme? Which top-nibble = Secure? | Determines all linker addresses and the SAU programming |
| 3 | What memory firewall is available? (GTZC MPCBB? RISAF? RIFSC? RIMC?) | Determines how `init_security` configures NS/S boundaries at block granularity |
| 4 | What crypto peripherals are available? HW AES? HW HMAC? | Determines whether `validator.rs` uses HW acceleration or SW fallback |
| 5 | Is there external flash? How is it decrypted on read (OTFDEC? MCE? not at all)? | Determines `init_external_flash` and how enclave ciphertext is delivered |
| 6 | Where is the enclave's ciphertext stored, and where does it execute (ESS / static)? | Determines `linker/platform.ld` and `host/<host>/linker/*` layout |
| 7 | What DMA controller exists, and does it carry CID tags for per-master filtering? | Determines whether block-load DMA can hit Secure SRAM directly |
| 8 | What UART is routed to the ST-Link VCP? Which clock feeds it, what baud is safe? | Determines `init_uart` and the baud rate used by smoke tests |

Memory note `project_stm32n657_architecture.md` has the L552-vs-N657
answers as a worked example.

## Step 1 — Design the memory map

Sketch the layout before writing linker scripts. Aim to mirror an
existing platform's structure unless the hardware forces otherwise:

| Region | Suggested home |
|---|---|
| Secure boot code (vector table + handlers + `_umb_start`) | Smallest Secure flash region or top of the bootable SRAM |
| Kernel `.text` (NSC API impls, kernel code) | Same Secure region, after boot |
| NSC veneers (`.umbra_nsc_api`) | A separate page-aligned Secure region exposed to NS via SAU |
| Kernel `.data` / `.bss` | Secure SRAM |
| ESS (Enclave Swap Space) | Secure SRAM, page-aligned, large enough for the working set |
| NS host code + data | A separate flash/SRAM region opened to NS by SAU |
| Enclave ciphertext on flash | External flash if you have it, otherwise NS internal flash |

L5 uses internal flash banks 0/1 split. N657 has no internal flash, so
everything lives in either AXISRAM2 (Secure boot + kernel) or
AXISRAM1 (split between NS host and Secure ESS).

## Step 2 — Decide the boot model

The kernel does not assume internal flash. Two boot models are
supported today:

### Model A — Internal-flash Secure boot (STM32L5)

Umbra is the reset vector and lives in Secure internal flash. The
device's option byte (`TZEN`) is set once via `make enable_security`.
This is the simplest path and works when the part has internal flash.

### Model B — FSBL loaded by Boot ROM from external flash (STM32N6)

The Boot ROM at a fixed address runs first, reads a **signed** FSBL
image from an external bus (XSPI on N657), authenticates it, and
copies it into SRAM. Umbra is the FSBL.

Implications:
- A signing tool runs after link (`STM32_SigningTool_CLI` for ST parts).
- The signed image has a header — the linker `ORIGIN` must account for
  it. On N657 the header is **0x400** bytes; payload starts at the
  load address + 0x400. Skipping this offset corrupts `.rodata` in
  ways that look exactly like a cache problem (see `fsbl-boot.md`).
- A flashing script (`tools/flash_<mcu>.sh`) drives the signing tool
  and `STM32_Programmer_CLI`.
- GDB cannot reset cleanly; use *attach without reset* for debug.

See [FSBL Boot (STM32N6)](../architecture/fsbl-boot.md) for the
worked N657 case.

## Step 3 — Create the platform skeleton

Add three crates under `src/hardware/platform/<mcu>/`:

```
src/hardware/platform/<mcu>/
  boot/                              # binary crate, the FSBL / Secure Boot
    Cargo.toml
    build.rs                         # link arg wiring (rustc-link-arg)
    asm/arm/startup_<mcu>.s          # reset handler, vector table, ctx save
    asm/arm/trampoline.s             # NS jump (BLXNS)
    .cargo/config.toml               # target + linker flags
    src/main.rs                      # secure_boot() entry, calls PlatformBoot
    src/platform_impl.rs             # PlatformBoot impl — most of the work
    src/secure_kernel.rs             # ESS miss handling (often L5 verbatim)
    src/handlers.rs                  # exception handlers + raw_print on fault
    src/api_impl.rs                  # umbra_*_imp NSC API implementations
    src/validator.rs                 # HMAC verify + AES decrypt
    src/raw_print.rs                 # minimal UART print used by handlers
    src/master_key.rs                # generated by tools/gen_key.py
    src/key_derivation.rs            # session-key derivation (often shared)
    src/crypto_impl.rs               # CryptoEngine wiring (HW or SW)
  drivers/
    Cargo.toml
    src/lib.rs
    src/rcc.rs                       # clocks
    src/gpio.rs                      # pin mode, AF
    src/uart.rs                      # debug UART
    src/hash.rs                      # SHA-256 / HMAC if HW available
    src/aes.rs                       # CRYP / SAES wrapper if HW available
    src/<firewall>.rs                # GTZC / RISAF / RIFSC / RIMC drivers
    src/<extflash>.rs                # OCTOSPI / XSPI driver if applicable
    src/<crypto-flash>.rs            # OTFDEC / MCE driver if applicable
  linker/
    platform.ld                      # SECTIONS for boot + kernel
```

The fastest way to bootstrap: copy the entire
`src/hardware/platform/stm32l552/` tree, rename it, and start replacing
peripheral bases and register layouts.

### Cargo wiring

Add the new boot and drivers crates to the workspace and to the
kernel's optional feature set so the kernel can compile against
platform-specific code if needed.

The boot crate's `build.rs` is where you set `cargo:rustc-link-arg`
for linker scripts — **assembly-linking flags must be in the binary
crate**, not in any rlib. The `feedback_asm_linking_rlib.md` memory
note exists because this was learned the hard way.

## Step 4 — Implement `PlatformBoot`

`src/kernel/src/platform/mod.rs` defines the trait. Every method has
to be implemented. The required behavior per method:

### `init_clocks`

Bring the part up to whatever clock the rest of the FSBL assumes.
Keep UART on a stable source (HSI on N657) so debug output survives
later PLL retuning. Enable the kernel clock dividers for any
peripheral the FSBL uses (HASH, AES, DMA, external flash).

### `init_gpio`

Configure board LEDs and the UART AF pins. Keep this minimal — the NS
host will configure its own GPIO later.

### `init_uart`

Configure the debug UART. Convention: 9600 baud on L5, 115200 baud on
N657 (HSI 64 MHz / 556 BRR). Print the banner and a `[UMBRASecureBoot]
Secure Boot started` line — `tools/smoke_test.sh` matches against that
prefix.

### `init_security`

This is the security-critical step and the one most likely to bite.
Concretely:

1. Program the **SAU** so NS regions map to the NS host bin and any
   shared buffers, while everything else stays Secure.
2. Program the **per-memory firewall** (GTZC MPCBB or RISAF). On
   STM32N6, **also** program RIFSC to open each Secure-only peripheral
   to Secure access (the Boot ROM may have left some flagged in a way
   that bites later). Tag DMA/NPU bus masters in **RIMC** if they need
   to touch Secure memory.
3. Enable **fault handlers** in `SCB.SHCSR` (MEMFAULT, BUSFAULT,
   USGFAULT, SECUREFAULT). Without this, faults silently escalate to
   HardFault and the CFSR diagnostic bits never appear.
4. Configure the **MPU** for kernel isolation.

The N657 implementation in
`src/hardware/platform/stm32n657/boot/src/platform_impl.rs` is the
most complete worked example.

### `init_kernel`

Initialize HASH and AES (HW preferred; fall back to SW where the part
lacks a peripheral, like L552's AES). Construct the `Kernel` instance.
Derive session keys from the master key + a fresh nonce. Run the
chained-measurement HMAC at boot — on N657 this also covers the NPU
model bytecode + weights via constants emitted by
`tools/measure_blobs.py`.

### `init_external_flash`

Return `false` if the part has no external flash. Otherwise:
- Configure the XSPI/OCTOSPI controller for memory-mapped read.
- Configure the decryption engine (OTFDEC on L562, MCE on N657) if
  enclaves are stored encrypted. Set its region keys from the FSBL's
  derived material; if you can't (MCE2 on N657's NUCLEO is currently
  passthrough), document the limitation rather than silently leaving
  decryption disabled.

### `configure_ns_boot`

Disable any Secure SysTick (re-enabled per-enclave by the SVC
handler). Set `VTOR_NS` to the NS host's vector-table address. On
parts where the IDAU classifies the NS-host flash region as Secure
for *data* reads (a Cortex-M architectural quirk, see the
[FreeRTOS example](../examples/freertos.md)) the vector table must
live in SRAM, not flash.

### `jump_to_ns`

Set `MSP_NS`, then `BLXNS` to the host entry point. This is almost
always identical to the L5 implementation — copy it verbatim.

## Step 5 — Wire up build and tooling

### `settings.sh`

Add a branch to the `MCU_VARIANT` switch:

```bash
elif [ "$MCU_VARIANT" = "<your_mcu>" ]; then
    export MCU=<your_mcu>
    export BOOT_FEATURES=""
    echo "[mcu_selection] Selected <BOARD>"
fi
```

Then add MCU-specific paths (OpenOCD config, flash start, target
arch) and the host-selection switch lower down. Smoke-test UART and
baud rate also go here.

### Linker scripts

Add `host/<your_host>/linker/{memory.ld,host.ld,sections.ld}`. The
key invariants:
- `_enclave_start` must be defined so the host can compute the flash
  address of the enclave header at runtime.
- NSC veneer addresses are PROVIDE'd in `host.ld` and must match the
  addresses the kernel actually emits — these are checked at link time
  with `--allow-multiple-definition` and PROVIDE.
- The vector table must live where `VTOR_NS` will point. On parts with
  the IDAU data-read quirk, that's SRAM.

### Top-level Makefile

If you need pre-build steps (key generation, blob measurement, model
extraction) add them as targets that `secureboot_build` depends on
— `generate_boot_measurements` is the N657 example.

### Flashing tool

Create `tools/flash_<mcu>.sh` if the deploy story is not "GDB load".
For STM32 parts that need signing, the pattern is:

1. `objcopy -O binary` the FSBL ELF.
2. `STM32_SigningTool_CLI -bin <bin> -nk -of <flags> -align <align>
    -la <load_addr> -ep <entry+1>`.
3. `STM32_Programmer_CLI -el <stldr> -d <signed.bin> <flash_addr>`.

Use environment variables for tool paths so non-macOS hosts can
override (`STM32CUBE_PROG_DIR`, `STM32_SIGNING_TOOL`,
`STM32_PROGRAMMER`, `STM32_EXT_LOADER_<mcu>`).

## Step 6 — Add a Non-Secure host

Mirror `host/bare_metal_arm/` into `host/bare_metal_<mcu>/`. Adjust:

- `linker/memory.ld` for the new MCU's memory map.
- `linker/host.ld` for the new NSC veneer addresses.
- `src/startup.s` for the NS reset handler.
- `src/main.c` — the enclave-scanning logic. If the NS host cannot
  read flash directly (RISAF12 on N657), compute the flash address
  from the linker-known `_enclave_start` and the AXISRAM1 NS base,
  instead of scanning bytes.
- `Makefile` — point `CFLAGS` at the new `mcpu`, include
  `../common/{inc,src}` so `umbra_hex.h` / `umbra_mem.c` are available.

For a FreeRTOS variant, copy `host/freertos_arm/` and apply the same
adjustments. Re-use the FreeRTOS-Kernel submodule already cloned into
`host/freertos_arm/lib/` — don't add a second submodule.

## Step 7 — Bring up incrementally

Don't try to boot the whole thing on first try. Phase the bring-up:

1. **Reach `_umb_start`** — UART silent, but JTAG shows the PC is
   inside the FSBL. Confirms reset vector / signing / Boot ROM hand-off.
2. **First UART byte** — `init_uart` works. The chip is alive.
3. **Banner + `Secure Boot started`** — `init_clocks` and `init_uart`
   are happy with each other.
4. **`Kernel Initialized`** — `init_security` + `init_kernel` are
   done.  This is where you'll hit ~half of the bring-up bugs.
5. **`Jumping to Non-Secure World`** — `configure_ns_boot` and
   `jump_to_ns` work.
6. **`Hello Non-Secure World!`** — the NS host runs.
7. **`Enclave created`** — `umbra_enclave_create` works, chained
   measurement matched.
8. **`Enclave terminated! R0=0x72CA33A8`** — the full Fibonacci runs.

Each of those eight checkpoints should be a separate commit.
N657's phases B → F follow this exact pattern.

## Common Bring-up Landmines

These are real bugs this codebase has hit. Pre-emptive awareness
saves days.

| Symptom | Cause | Fix |
|---|---|---|
| `.rodata` reads back zeros after FSBL boot | Linker `ORIGIN` didn't account for the signing-header offset | Add `_signing_header_size = 0x400` and offset all addresses |
| UART silent after PLL retune | UART was on PLL1; PLL1 went down during retune | Run UART off HSI so it's insulated from PLL1 |
| Vector-table data reads fault on Cortex-M with TrustZone | IDAU classifies the NS flash region as Secure for **data** reads | Put the NS vector table in SRAM, set `VTOR_NS` accordingly |
| `vStartFirstTask` faults inside FreeRTOS init | FreeRTOS reads `*(VTOR[0])` to reset MSP, which is a data read from the vector table base | Provide a `vStartFirstTask` override that loads MSP from a linker symbol; link order matters |
| FreeRTOS SVC handler silently ignores `START_SCHEDULER` | V11 uses **SVC #102**, not SVC #0 | Match the SVC number in the override |
| Fault handlers print no CFSR diagnostic | NS SHCSR fault enables not set (Secure SHCSR is set by FSBL, NS one is not) | NS host must `SCB->SHCSR |= (1<<16)|(1<<17)|(1<<18)` |
| Thumb bit dropped from function pointers in a SRAM vector table | `.thumb_func` is lost across `R_ARM_ABS32` relocations in `.data` | Define fault handlers in C, not assembly |
| RISAF region "doesn't apply" | The IDAU view spans **two** RISAFs (RISAF7 for FLEXRAM + RISAF2 for AXISRAM1) | Configure both, not just one |
| HASH peripheral returns garbage on N657 | DATATYPE was left at word-swap default; payload is byte stream | Set CR.DATATYPE = 0b10 (byte-swap) |
| NPU IRQ never fires | `.thumb_set` shadowed the strong handler; or peripheral was clocked wrong | Drop the alias; enable IC6 for NPU at rated frequency |
| Boot ROM accepts the unsigned image but execution faults on entry | Entry address missing the Thumb LSB | `-ep <reset_handler_addr + 1>` |
| Master key mismatch makes attestation fail silently | `tools/gen_key.py` was run but the per-MCU `master_key.rs` wasn't regenerated | Always regenerate all three; see `tools/README.md` |

## Step 8 — Land smoke tests

Add a golden UART log under `tools/` (or extend the existing one) so
`smoke_test.sh` exercises your platform alongside the existing ones.
Re-run `smoke_test.sh`, `smoke_test_fault.sh`, and
`smoke_test_fault_runtime.sh` on hardware. Fault-injection smoke tests
catch the case where your fault handlers eat exceptions silently.

## What you do *not* need to port

A lot of the kernel travels unchanged. In particular:
- `src/kernel/` (enclave descriptors, key store, ESS data structures)
- `src/hardware/architecture/arm/` (SAU, MPU, mmio, vector tables)
- `validator.rs` (HMAC verify + AES decrypt — only the `CryptoEngine`
  wiring is platform-specific)
- The NSC veneer assembly (`asm/arm/nsc_veneers.s`)
- The host-side enclave header layout and `protect_enclave.py`

If you find yourself rewriting any of those, that is a signal the
work belongs *in the kernel* and not in your platform crate. Prefer
extending the `PlatformBoot` trait over forking the kernel.
