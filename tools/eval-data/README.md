# eval-data — provenance of the N657 measurement campaigns

Two campaigns, same shape: 30 attestation quotes and 30 chained enclave updates
(versions of `ndes`, `blob_len = 5808`, every one accepted). The `*_cyc` columns
are DWT `CYCCNT` deltas taken by the firmware itself
(`stm32n657/boot/src/attest_imp.rs`, CPU at 800 MHz, so 1 cycle = 1.25 ns); the
`*_s` columns are host-side wall clock. Reproduce with `tools/eval_attest.sh`.

| file | tag | date |
|---|---|---|
| `n657_attest_update_2026-07-28.csv` | pkg-tag **v1** (75-byte preimage) | 2026-07-28 |
| `n657_attest_update_v2_2026-08-10.csv` | pkg-tag **v2** (91-byte preimage) | 2026-08-10 |

**Quote the v2 file.** v1 is kept because the paper's earlier numbers came from
it and because the pair is the only direct measurement of what widening the
preimage costs.

## v1 campaign (2026-07-28)

Campaign means over the 30 updates, with the sample standard deviation:

| phase | column | mean (cycles) | mean (ms) | sd (cycles) |
|---|---|---:|---:|---:|
| copy package to Secure | `copy_cyc` | 1 047 293 | 1.309 | 43 |
| **authenticate** (`parse_and_verify`) | `auth_cyc` | **17 548** | **0.0219** | **83** |
| probe both slots | `probe_cyc` | 10 208 985 | 12.761 | 515 875 |
| flash write | `flash_cyc` | 55 563 463 | 69.454 | 2 121 386 |
| re-verify written slot | `verify_cyc` | 4 780 539 | 5.976 | 456 561 |
| total | — | 71 617 828 | 89.522 | — |

`auth` is 0.0245 % of the total; flash programming is 77.6 %.

## v2 campaign (2026-08-10) — the one to cite

Same board, same workload, same harness; firmware rebuilt at `295fd0a` so the tag
covers the full 48-byte header. Versions v4..v33, 30/30 accepted.

| phase | column | mean (cycles) | mean (ms) | sd (cycles) |
|---|---|---:|---:|---:|
| copy package to Secure | `copy_cyc` | 1 047 296 | 1.309 | 173 |
| **authenticate** (`parse_and_verify`) | `auth_cyc` | **18 303** | **0.0229** | **69** |
| probe both slots | `probe_cyc` | 10 187 953 | 12.735 | 1 035 298 |
| flash write | `flash_cyc` | 53 924 281 | 67.405 | 1 667 694 |
| re-verify written slot | `verify_cyc` | 4 125 482 | 5.157 | 353 551 |
| total | — | 69 303 315 | 86.629 | — |

`auth` is 0.0264 % of the total; flash programming is 77.8 %. Quote generation is
20 500 cycles (25.6 µs), statistically unchanged from v1's 20 567 — the quote
preimage is still 83 bytes, so this is the control that shows the campaign is
measuring the tag change and not drift.

**The `auth` mean above excludes sample #0** (n = 29). Sample #0 reads 15 374
cycles, ~16 % *below* steady state, because the first update runs immediately
after the 30-quote phase with the HASH block already exercised, whereas every
later update follows a device reboot. Including it gives mean 18 206 with sd 539
— a sd inflated 8× by one structural outlier. Report the steady state and say so.

### What widening the preimage cost

**+4.30 %** on `auth`: 17 548 → 18 303 cycles, i.e. 0.94 µs. Predicted before the
run from a cycle budget (75 and 91 bytes both pad to three inner blocks, so no
extra SHA-256 compression — only four more words pushed to `HASH_DIN`) as
"~18 300 cycles, +4.2 %". Every other phase is unchanged within noise: `copy`
moves +0.00 %, `probe` −0.21 %. `flash` (−2.95 %) and `verify` (−13.70 %) differ
by more, but those phases are dominated by NOR programming and by A/B slot state,
not by anything v2 touches.

## Caveats these numbers must carry

1. **Built at `opt-level = 0`.** The workspace release profile is
   `opt-level = 0` (root `Cargo.toml`, `[profile.release]`, deliberate — it
   matches boot's pre-workspace setting). Every cycle count here is
   un-optimised code, `auth` most of all: authenticating a package is *one*
   HMAC-SHA-256 over a 91-byte preimage — five SHA-256 compression-function
   calls — issued to the HASH IP by `attest_imp.rs::hw_hmac_single`. The rest of
   the 17.5 kcycles is the surrounding un-optimised parse, copy and marshalling.
   So **`auth_cyc` is not a hardware-hash throughput figure**: the HASH engine is
   idle for the large majority of that window, and citing the phase as evidence
   about the accelerator is wrong in both directions (it understates the IP and
   overstates the cost of the proved logic).

2. **Say which tag a number came from.** The 2026-07-28 file is v1 (75-byte
   preimage); the 2026-08-10 file is v2 (91 bytes, full header covered). They
   differ measurably on `auth` and only on `auth`.

3. **The `auth` dispersion is not "below timer resolution".** DWT resolution is
   1 cycle = 1.25 ns; the `auth_cyc` sample sd is 83 cycles under v1 and 69 under
   v2, i.e. tens of times the timer resolution. What it is below is the
   **reporting** resolution of a millisecond table: 69 cycles = 0.00009 ms, which
   rounds to 0.00 at two decimals. Prose that says "standard deviation below
   timer resolution" is false; "below the 0.01 ms resolution the table reports
   at" is the defensible form.

4. **The master key must be pinned across a campaign.** Export
   `UMBRA_KEEP_MASTER_KEY=1` for the whole flash-and-measure session.
   `tools/gen_key.py` otherwise rotates on every invocation, and because
   `key_gen` is a dependency of several make targets that can run concurrently,
   the four copies of the key (`master_key.bin` plus three `master_key.rs`) can
   end up holding four *different* keys — at which point the device's tags fail
   host verification and the run is worthless. This happened on 2026-08-10 and
   presented as `tag: FAIL` on a board that had just been flashed correctly.
