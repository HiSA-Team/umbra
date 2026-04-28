# Formal Verification

## Overview

Umbra's integrity model is formally verified using [ProVerif](https://prosecco.gforge.inria.fr/personal/bblanche/proverif/), an automatic cryptographic protocol verifier.

Two models are maintained in `docs/formal/`:

| Model | File | Scenario |
|---|---|---|
| L552 (SW AES) | `UmbraIntegrityFixValidator.pv` | HMAC over ciphertext, trusted Validator |
| L562 (OTFDEC) | `UmbraIntegrityRaceValidatorFix.pv` | HMAC over plaintext, untrusted Validator channel |

## What Is Verified

Both models prove two key properties:

1. **Execution implies request**: Every executed block was explicitly requested by the kernel
   ```
   inj-event(Execute(b, d)) ==> inj-event(Request(b))
   ```

2. **Execution implies registration**: Every executed block was registered in the ESS
   ```
   event(Execute(b, d)) ==> event(RegisterBlock(b, d))
   ```

These properties guarantee that an attacker cannot cause the CPU to execute unvalidated code, even if they can tamper with flash contents or DMA transfers.

## Running Verification

Install ProVerif, then:

```bash
cd docs/formal
proverif UmbraIntegrityFixValidator.pv
proverif UmbraIntegrityRaceValidatorFix.pv
```

Both should report `RESULT` lines ending with `is true`.

## When to Re-verify

Re-run ProVerif after modifying:
- `Kernel::handle_ess_miss` (block loading and validation flow)
- `validate_block` (HMAC computation or comparison)
- Fault dispatchers in `handlers.rs` (UsageFault, SecureFault, BusFault)
- On-flash block layout in `protect_enclave.py`
- ESS cache insertion or eviction logic
