//! Enclave creation: the BFS EFB block loader + chained measurement.
//! Split out of `mod.rs` to respect the 600-LOC hard cap.
use super::*;

/// Validate, load, and measure the EFB-divided enclave whose `UmbraEnclaveHeader`
/// lives at `base`; returns its id. The pipeline mirrors L552's
/// `api_impl/enclave_create` + `secure_kernel`:
///
/// 1. Parse the header → `num_blocks = code_size / TOTAL_BLOCK_SIZE`.
/// 2. Seed the chained measurement (`chain_state = MASTER_KEY`).
/// 3. **BFS** from block 0: for each reachable block, fold its binding input
///    `[block_id || ciphertext || meta]` into the chain, copy the ciphertext
///    into its ESS slot (`ESS_BASE + idx*CODE_BLOCK_SIZE`), AES-128-CTR-decrypt
///    in place, then enqueue the blocks named in its `meta` reachable list.
/// 4. Fold the on-image relocation table into the chain.
/// 5. `finalize`: constant-time compare the chain against `header.hmac` — a
///    tampered/unsigned blob is rejected before the enclave is registered.
///
/// The blocks reassemble contiguously in the Secure ESS, so the enclave runs
/// from `ESS_BASE` exactly as the host-image layout intended; the untrusted host
/// only ever holds the encrypted blocks.
pub fn create(base: u32) -> UmbraResult<u32> {
    // SAFETY: M-mode parse of the host-image enclave header at `base`.
    let header = match unsafe { UmbraEnclaveHeader::from_address(base) } {
        Some(h) => h,
        None => {
            return Err(UmbraError::NscArgInvalid {
                which: "enclave magic invalid",
            })
        }
    };

    let st = state();
    let id = st.next_id;
    if !id_is_valid(id) || (id as usize) >= MAX_ENCLAVES {
        return Err(UmbraError::EnclaveStateInvalid);
    }

    let blob_base = base + UMBRA_HEADER_SIZE;
    let code_size = header.code_size; // encrypted-blocks region = N * TOTAL_BLOCK_SIZE
    let num_blocks = code_size / TOTAL_BLOCK_SIZE;
    if num_blocks == 0 || (num_blocks as usize) > MAX_EFBS {
        return Err(UmbraError::EnclaveStateInvalid);
    }

    // Seed the chained measurement + derive the AES key through the
    // `CryptoEngine` (mirrors L552 `begin_measurement` +
    // `key_derivation::derive_enc_key`).
    let mut crypto = crypto_impl::UmbraCryptoEngine::new();
    let mut chain_state = crypto_impl::MASTER_KEY;
    let enc_key = crypto_impl::derive_enc_key(&mut crypto)?;

    // Trap-fill every ESS slot up front so any block that is NOT resident faults
    // to M on first instruction fetch (demand-load trigger). Block 0 (entry) is
    // installed during the BFS below; blocks 1..N stay trap-filled and fault in
    // on demand via `handle_ess_miss`.
    let mut block_loaded = [false; MAX_EFBS];
    for b in 0..num_blocks {
        // SAFETY: slot b is within the enclave's ESS region (b < num_blocks ≤ MAX_EFBS).
        unsafe { trap_fill_slot(ESS_BASE + b * CODE_BLOCK_SIZE) };
    }

    // BFS over the block graph, starting at block 0 (the entry block).
    let mut loaded_mask: u32 = 0;
    let mut queue = [0u8; MAX_EFBS];
    let mut head = 0usize;
    let mut tail = 0usize;
    queue[0] = 0;
    tail += 1;
    loaded_mask |= 1;

    while head < tail {
        let idx = queue[head] as u32;
        head += 1;

        let blk = blob_base + idx * TOTAL_BLOCK_SIZE;
        let meta_ptr = (blk + BLOCK_META_OFFSET) as *const u8;
        let ct_ptr = (blk + BLOCK_CT_OFFSET) as *const u8;

        // Fold this block into the chain over [block_id(4) || ciphertext || meta]
        // — byte-for-byte the `binding_input` protect_enclave.py signs. (The
        // per-block `sig` at offset 0 is checked by the runtime ESS-miss path,
        // not here; the final chain compare catches create-time tampering.)
        let mut vbuf = [0u8; 4 + CODE_BLOCK_SIZE as usize + 32];
        vbuf[0..4].copy_from_slice(&idx.to_le_bytes());
        // SAFETY: ciphertext + meta lie within the host-image block we parsed.
        unsafe {
            core::ptr::copy_nonoverlapping(
                ct_ptr,
                vbuf[4..].as_mut_ptr(),
                CODE_BLOCK_SIZE as usize,
            );
            core::ptr::copy_nonoverlapping(
                meta_ptr,
                vbuf[4 + CODE_BLOCK_SIZE as usize..].as_mut_ptr(),
                32,
            );
        }
        let mut folded = [0u8; 32];
        crypto.hmac(&chain_state, &vbuf, &mut folded)?;
        chain_state = folded;

        // Install ONLY the entry block (0) at create; the rest stay trap-filled
        // and fault in on demand. (All blocks are still folded into the chain
        // above so the measurement matches protect_enclave.py.)
        if idx == 0 {
            let ess_slot = ESS_BASE + idx * CODE_BLOCK_SIZE;
            // SAFETY: block 0's ESS slot inside the enclave region.
            unsafe { install_block(&mut crypto, &enc_key, ct_ptr, ess_slot) };
            block_loaded[0] = true;
        }

        // Enqueue unvisited reachable blocks named in this block's meta
        // ([count | idx*count | pad]).
        // SAFETY: meta is the 32-byte region we just folded.
        let count = unsafe { core::ptr::read_volatile(meta_ptr) } as usize;
        for ri in 0..count.min(MAX_REACHABLE) {
            // SAFETY: ri < MAX_REACHABLE ≤ meta payload.
            let nb = unsafe { core::ptr::read_volatile(meta_ptr.add(1 + ri)) };
            let nb_idx = nb as u32;
            if (nb as usize) < MAX_EFBS && nb_idx < num_blocks && (loaded_mask & (1 << nb)) == 0 {
                queue[tail] = nb;
                tail += 1;
                loaded_mask |= 1 << nb;
            }
        }
    }

    // Fold the on-image relocation table into the chain (after the BFS fold,
    // matching protect_enclave.py). reloc_count == 0 → no-op.
    let reloc_count = header.reloc_count as u32;
    if reloc_count > 0 {
        let reloc_flash = blob_base + code_size;
        // SAFETY: reloc table immediately follows the blocks in the host image.
        let reloc_bytes = unsafe {
            core::slice::from_raw_parts(reloc_flash as *const u8, (reloc_count * 4) as usize)
        };
        let mut folded = [0u8; 32];
        crypto.hmac(&chain_state, reloc_bytes, &mut folded)?;
        chain_state = folded;
    }

    // Finalize: constant-time compare the chain against the header's reference.
    let expected = header.hmac;
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= chain_state[i] ^ expected[i];
    }
    if diff != 0 {
        raw_print::print_str("[UMBRASecureBoot] chained-measurement FAIL\n");
        let mut exp8 = [0u8; 8];
        let mut got8 = [0u8; 8];
        exp8.copy_from_slice(&expected[..8]);
        got8.copy_from_slice(&chain_state[..8]);
        return Err(UmbraError::MeasurementMismatch {
            expected: exp8,
            got: got8,
        });
    }
    raw_print::print_str("[UMBRASecureBoot] chained-measurement OK\n");

    // Block 0 + trap-fills are now in ESS — sync instruction fetch before the
    // enclave runs (QEMU re-translates the slots; I-cache sync on real HW).
    fence_i();

    let mut block_counter = [0u32; MAX_EFBS];
    block_counter[0] = 1; // entry block is resident
    st.slots[id as usize] = Slot {
        descriptor: EnclaveDescriptor {
            id,
            flash_base: base,
            ram_base: ESS_BASE,
            code_size: num_blocks * CODE_BLOCK_SIZE, // reassembled ESS footprint
            entry_point: ESS_BASE,                   // entry block first → entry at ESS_BASE
            is_loaded: true,
        },
        result: 0,
        used: true,
        suspended: false,
        saved_ctx: ZERO_FRAME,
        num_blocks,
        block_loaded,
        block_counter,
    };
    st.next_id += 1;

    Ok(id)
}
