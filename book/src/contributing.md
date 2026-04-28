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
- **Target**: `thumbv8m.main-none-eabi` (Cortex-M33)
- **No `std`**: all crates are `#![no_std]`
- **Naming**: snake_case for functions/variables, UPPER_CASE for statics, PascalCase for types
- **Assembly**: separate `.s` files in `asm/` directories (not `global_asm!`)

## Testing

### Compilation Gate

Both variants must compile without warnings:

```bash
# L552 (default)
source settings.sh   # select L552
./rebuild_all.sh

# L562
source settings.sh   # select L562
./rebuild_all.sh
```

### On-Target Smoke Tests

```bash
export UMBRA_UART=/dev/cu.usbmodem211203
tools/smoke_test.sh                    # Normal boot + enclave execution
tools/smoke_test_fault.sh              # Fault injection
tools/smoke_test_fault_runtime.sh      # Runtime fault recovery
```

### Formal Verification

```bash
cd docs/formal
proverif UmbraIntegrityFixValidator.pv
proverif UmbraIntegrityRaceValidatorFix.pv
```

## Pull Request Process

1. Create a branch from `main`
2. Ensure both L552 and L562 build with 0 warnings
3. Run smoke tests on at least one hardware variant
4. Open a PR with a description of what changed and why
