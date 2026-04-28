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
   - **Fetch**: DMA transfer from flash to scratch buffer (L552) or CPU copy from OCTOSPI (L562)
   - **Validate**: HMAC-SHA256 verification against on-flash signature
   - **Decrypt**: AES-CTR decryption (L552 software, L562 via OTFDEC)
   - **Evict**: If cache is full, evict LFU (Least Frequently Used) block
   - **Install**: DMA copy to ESS slot, MPCBB flip to Secure, cache invalidate
6. Fault handler returns — CPU re-executes the faulting instruction, now hitting valid code

## Block Layout on Flash

Each block on flash has this structure (with `chained_measurement` + `ess_miss_recovery` features):

```
[HMAC (32B)] [Metadata (32B)] [Ciphertext (256B)]
 +-- 64B header --+               +-- EFB payload --+
```

Total: 320 bytes per block.

## Prefetch Pipeline

To reduce ESS miss latency, Umbra speculatively prefetches reachable blocks. Each block's metadata includes a reachability list — blocks that are control-flow successors. After installing a block, the prefetch pipeline asynchronously loads reachable blocks via DMA.
