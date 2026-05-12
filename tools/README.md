# Umbra tools

Build-time helpers, deployment harness, smoke-test scripts. Most are invoked
indirectly by `./rebuild_all.sh` and per-host `Makefile`s.

## Bootstrapping a fresh clone

`tools/master_key.bin` is **not** committed. The Rust constants it pairs with
(`src/hardware/platform/stm32{l552,n657}/boot/src/master_key.rs`) **are**
tracked so a fresh clone can `cargo check` immediately. Before flashing or
running the chained-measurement HMAC over a real enclave, regenerate a
matching key set:

```bash
python3 tools/gen_key.py
```

That writes:

- `tools/master_key.bin` — 32-byte raw key consumed by `protect_enclave.py`
- `src/hardware/platform/stm32l552/boot/src/master_key.rs` — Rust constant compiled into the L552 / L562 FSBL
- `src/hardware/platform/stm32n657/boot/src/master_key.rs` — Rust constant compiled into the N657 FSBL

All three must stay in sync. The `.bin` and the two `.rs` files all carry the
same key bytes; mismatched copies break attestation silently.

## Other scripts

| Script | Purpose |
|---|---|
| `gen_key.py` | Generate a fresh master key (see above). |
| `protect_enclave.py` | Post-link: compute chained-measurement HMAC and patch it into the enclave header. |
| `measure_blobs.py` | Compute boot-time chained-HMAC constants for the N657 FSBL. |
| `image_to_c_array.py` | Convert an input image to a C `const uint8_t[]` for the NPU object-detection demo. |
| `extract_bytecode.py` | Extract the NPU model bytecode from an ST Edge AI build output. |
| `flash_n657.sh` | Flash FSBL + host binary + NPU artifacts to a NUCLEO-N657X0-Q via STM32CubeProgrammer. Override the STM32CubeProgrammer install dir via `STM32CUBE_PROG_DIR=…` on Linux. |
| `smoke_test.sh`, `smoke_test_fault.sh`, `smoke_test_fault_runtime.sh` | UART golden-log comparison harness, plus fault-injection variants. |

## Demo-only inputs

Anything under `tools/` that's *not* in `.gitignore` and *not* a script is a
demo input intended to make a fresh clone build out of the box. The generated
`master_key.bin` after running `gen_key.py` is research-grade; do not reuse
the generated value across machines or commit it.
