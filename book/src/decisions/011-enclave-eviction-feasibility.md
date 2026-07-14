# ADR 011 — Enclave block eviction: trap mechanism and cache model

## Status
Accepted (2026-07-05)

## Context
The ESS is a demand-paged cache of an enclave's 256-byte code blocks. To run an enclave larger
than the resident-block budget, or to make room for a second enclave, the kernel must **evict** a
block: free its slot and re-load it (or reject the access) when touched again. Two questions
gate a safe design, and the answers turned out to be silicon-specific:

1. **Can an access to an evicted block be trapped synchronously — for DATA as well as
   instructions?** The existing demand-paging fills unloaded slots with UDF, which traps only
   *instruction fetches*. A cross-block **data** load to an evicted slot must also fault, or the
   computation silently reads garbage. On L552/L562 (Cortex-M33) there is no such data trap — a
   prior attempt paged data blocks and corrupted results silently (reverted).
2. **Can blocks be RELOCATED** (a true set-associative cache with fewer physical slots than
   logical blocks), which requires address translation?

## Decision

**The synchronous data trap is the MPU, not the memory firewall.** On N657 the enclave runs
unprivileged with `PRIVDEFENA=1`, so any address outside its explicit MPU regions raises a
precise, synchronous `MemManage` fault on *both* data loads and instruction fetches. The RISAF
memory firewall was evaluated and rejected for this: a denied data read returns zero (read-as-
zero) and only logs to the asynchronous illegal-access controller — RM0486 §3.5.3 states an
illegal access raises a bus error **only if it is an instruction fetch**. So the RISAF gives the
same instruction-only trap as UDF-fill and cannot drive a synchronous data restore. The MPU
`hide → MemManage → restore` round-trip is hardware-verified (instruction-fetch fault at the
entry block, handler restores the region and resumes; the enclave completes normally).

**A transparent intra-enclave cache is infeasible on N657, so eviction is inter-enclave.** A
cache with fewer physical slots than logical blocks must relocate blocks to arbitrary slots,
which needs address translation — but the M55 implements PMSA (protection only, no MMU/translation).
The software alternative — routing every inter-block branch through a runtime indirection table —
was spiked and rejected: the enclave is one function split into fixed contiguous 256-byte blocks,
and its inter-block control flow is dominated by **narrow PC-relative branches** (on a
representative app, ~70/124 cross-block edges are ±254 B conditional or ±2 KB unconditional loop
back-edges and if/else inside functions that straddle a block boundary). After linking, those
branches carry **no relocations** and cannot be widened in place, so indirecting them is a
compiler-level control-flow rewrite that must be final at build time — which contradicts load-time
relocation, and any rewrite changes the byte-exact chained measurement. The kernel-side change
(block-id → slot lookup) is trivial; the branch fixup is not.

The eviction that IS feasible is **inter-enclave**: time-multiplex the EFBC across *different*
enclaves. Evict enclave A's whole EFBC to an SRAM backing over DMA, MPU-fence A's region, run
enclave B in the freed EFBC, and restore A on re-entry. Each enclave keeps its own fixed
contiguous layout, so no branch relocation is required. The evict→backing→restore round-trip is
hardware-verified (the enclave survives a scramble of its EFBC between evict and restore).

## Consequences
- Per-block hide/restore is safe on N657 (MPU trap) and unsafe for data on L552/L562 (no data
  trap) — the demand-paging landmine is a silicon property, not a bug.
- Running a single enclave larger than the EFBC is out of reach on N657 without an enclave
  compiler/toolchain change (indirected branches or overlays); this is documented, not attempted.
- The reusable primitives — DMA loader, async DMA→IRQ→PendSV engine, and the MPU trap+restore —
  are hardware-verified and shared with the [ESS model](../architecture/ess-model.md) and the
  N657 crypto DMA path. Inter-enclave scheduling (which enclave to evict, when) is the remaining
  work; the mechanism underneath it is proven.
