# Enclave Swap Space (ESS)

## Concept

Enclaves are stored encrypted in flash. They cannot execute directly from flash — they must be loaded into Secure SRAM, validated (HMAC), and decrypted (AES) before execution.

The Enclave Swap Space (ESS) manages this process as a **demand-paged cache**:

- Enclave code is split into 256-byte **Enclave Flash Blocks (EFBs)**
- Only a subset of blocks are loaded into SRAM at any time
- When the CPU fetches an instruction from an unloaded block, a **UsageFault (UNDEFINSTR)** fires
- The fault handler loads the missing block on-demand (ESS miss recovery)

## ESS Miss Recovery Flow

1. Enclave executes code in block N
2. CPU fetches instruction from block M (not yet loaded) — hits a **UDF trap** (undefined instruction)
3. **UsageFault** fires, assembly trampoline saves context, calls `umbra_usage_fault_dispatch()`
4. Dispatcher identifies the faulting PC, looks up which enclave and block it belongs to
5. `handle_ess_miss()` is called:
   - **Fetch**: DMA transfer from flash to scratch buffer (L552) or CPU copy from OCTOSPI (L562); on N657 the loader (`load_block_n657`) copies flash→ESS over **HPDMA1** (the memory-mapped XSPI2 window is MCE-decrypted on read)
   - **Validate**: HMAC-SHA256 verification against on-flash signature
   - **Decrypt**: AES-CTR — L552 = software (T-table); L562 = OTFDEC transparent decrypt at the OCTOSPI controller; N657 = native CRYP1 CTR mode, **DMA-fed** over dual HPDMA1 channels (mem→CRYP_DIN + CRYP_DOUT→mem)
   - **Evict**: if the cache is full, evict a block — but eviction safety is platform-dependent, see [Eviction feasibility](#eviction-feasibility) below
   - **Install**: DMA copy to ESS slot, MPCBB flip to Secure, cache invalidate
6. Fault handler returns — CPU re-executes the faulting instruction, now hitting valid code

The N657 crypto path is fully DMA: HW SHA-256 and AES-CTR are fed by HPDMA1 rather than CPU
FIFO loops — see [ADR 011](../decisions/011-enclave-eviction-feasibility.md) for the eviction
analysis that shares the same DMA + trap machinery.

## Block Layout on Flash

Each block on flash has this structure (with `chained_measurement` + `ess_miss_recovery` features):

```
[HMAC (32B)] [Metadata (32B)] [Ciphertext (256B)]
 +-- 64B header --+               +-- EFB payload --+
```

Total: 320 bytes per block.

## Prefetch Pipeline

To reduce ESS miss latency, Umbra speculatively prefetches reachable blocks. Each block's metadata includes a reachability list — blocks that are control-flow successors. After installing a block, the prefetch pipeline asynchronously loads reachable blocks via DMA.

On **N657** the async engine is built and hardware-verified: a block loads in the background
on an HPDMA1 channel while the CPU keeps running; the transfer-complete IRQ defers the install
to **PendSV** (lowest priority, so the cache-maintenance window never overlaps unprivileged
enclave code). Nothing blocks — the enclave runs while blocks stream in.

## Eviction feasibility

Eviction (freeing an ESS slot to make room) has a hard silicon dependency, and the safe design
differs per platform:

- **L552 / L562 (Cortex-M33):** there is **no synchronous data-read trap**. Unloaded blocks are
  UDF-filled, which traps *instruction fetches* only — a cross-block **data** load to an evicted
  slot silently reads the fill instead of faulting, so the computation is silently corrupted.
  Evicting data-referencing blocks is therefore unsafe and is not done.
- **N657 (Cortex-M55):** the enclave runs unprivileged with `PRIVDEFENA=1`, so the **MPU** gives
  a precise, synchronous `MemManage` fault on *any* access — data load or instruction fetch — to
  an address outside its regions. That is the synchronous data trap the M33 lacks (the RISAF
  memory firewall does **not** provide it: a denied data read returns zero and logs asynchronously,
  per RM0486 §3.5.3 an illegal access raises a bus error only for instruction fetches). The MPU
  hide→fault→restore round-trip is hardware-verified.
- A transparent **intra-enclave** cache (fewer physical slots than logical blocks) is **infeasible**
  on N657: it needs address translation, but the M55 has no MMU (PMSA is protection-only), and the
  enclave's inter-block control flow uses narrow PC-relative branches that assume a contiguous
  layout and carry no relocations to fix up. The feasible eviction is **inter-enclave** — time-
  multiplex the EFBC across different enclaves (evict enclave A's EFBC to an SRAM backing over DMA,
  run B, restore A on re-entry); each enclave keeps its fixed layout, so no branch relocation is
  needed. See [ADR 011](../decisions/011-enclave-eviction-feasibility.md).
