# Contributing

## Build from Source

```bash
git clone https://github.com/HiSA-Team/umbra.git
cd umbra
source settings.sh
./rebuild_all.sh
```

See [Prerequisites](getting-started/prerequisites.md) for required tools.

## Code Conventions

- **Rust edition**: 2021, nightly toolchain
- **Target**: `thumbv8m.main-none-eabi` (Cortex-M33 *and* Cortex-M55 in
  the M33-compatible subset)
- **No `std`**: all crates are `#![no_std]`
- **Naming**: snake_case for functions/variables, UPPER_CASE for statics, PascalCase for types
- **Assembly**: separate `.s` files in `asm/` directories (not `global_asm!`)

## Testing

### Compilation Gate

All three MCU variants must compile without warnings:

```bash
# L552 (default Cortex-M33)
export MCU_VARIANT=stm32l552
source settings.sh
./rebuild_all.sh

# L562 (Cortex-M33 with hardware AES + OCTOSPI)
export MCU_VARIANT=stm32l562
source settings.sh
./rebuild_all.sh

# N657 (Cortex-M55 FSBL)
export MCU_VARIANT=stm32n657
source settings.sh
./rebuild_all.sh
```

For the N657 NPU object-detection demo, the ST Edge AI artifacts under
`host/object_detection_n657/Model/NUCLEO-N657X0-Q/` are tracked in the
repo — no extra tooling is needed just to build. Regenerating those
artifacts requires installing ST Edge AI (`stedgeai` CLI).

### On-Target Smoke Tests

```bash
# L5: 9600 baud; N657: 115200
export UMBRA_UART=/dev/cu.usbmodem211203
tools/smoke_test.sh                    # Normal boot + enclave execution
tools/smoke_test_fault.sh              # Fault injection
tools/smoke_test_fault_runtime.sh      # Runtime fault recovery
```

The script compares UART output against `tools/golden_uart.log` for the
active MCU variant.

### Formal Verification

```bash
cd docs/formal
proverif UmbraIntegrityFixValidator.pv
proverif UmbraIntegrityRaceValidatorFix.pv
```

## Adding a New Board

See [Porting to a New Board](porting/porting-a-new-board.md) for a
step-by-step recipe based on the L5 → N657 work in this repo. It
covers the `PlatformBoot` PAL trait, where to put per-board code,
which build/system pieces to wire up, and the bring-up landmines this
codebase has hit before.

## Pull Request Process

1. Create a branch from `main`.
2. Ensure all three MCU variants build with 0 warnings.
3. Run smoke tests on at least one hardware variant. If a change
   touches the FSBL boot flow, retry on N657 (its Boot ROM behavior
   is the most fragile path).
4. Open a PR with a description of what changed and why. Reference any
   bring-up landmines you hit so the next person can find them.
