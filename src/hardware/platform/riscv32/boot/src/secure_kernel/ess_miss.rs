//! Runtime ESS-miss recovery (demand-load) + LFU block eviction.
//! Split out of `mod.rs` to respect the 600-LOC hard cap.
use super::*;

/// Runtime ESS-miss recovery — the RISC-V counterpart of L552's
/// `handle_ess_miss`. Called from the trap handler when the running enclave
/// fetches from a trap-filled (unloaded) block: fetch the block from the host
/// image, re-validate its per-block `sig`, evict a victim if the cache is full,
/// AES-decrypt-install it, and `fence.i`. The faulting instruction is then
/// re-executed (the handler does NOT advance `mepc`). Returns `Err` if the block
/// id is out of range or the per-block HMAC fails (tampered block).
pub fn handle_ess_miss(block_idx: u32) -> Result<(), UmbraError> {
    let st = state();
    let idx = match st.current {
        Some(i) => i,
        None => return Err(UmbraError::EnclaveStateInvalid),
    };
    let slot = &st.slots[idx];
    if block_idx >= slot.num_blocks || (block_idx as usize) >= MAX_EFBS {
        return Err(UmbraError::EnclaveStateInvalid);
    }
    let flash_base = slot.descriptor.flash_base;

    // On-image block layout: [sig(32) | meta(32) | ct(256)] at base+48+idx*320.
    let blk = flash_base + UMBRA_HEADER_SIZE + block_idx * TOTAL_BLOCK_SIZE;
    let sig_ptr = blk as *const u8;
    let meta_ptr = (blk + BLOCK_META_OFFSET) as *const u8;
    let ct_ptr = (blk + BLOCK_CT_OFFSET) as *const u8;

    // Re-validate the per-block HMAC over [block_id || ct || meta] under the
    // derived hmac_key (the runtime Validator). A tampered block is refused
    // before it is decrypted or installed.
    let mut crypto = crypto_impl::UmbraCryptoEngine::new();
    let hmac_key = crypto_impl::derive_hmac_key(&mut crypto)?;
    let mut vbuf = [0u8; 4 + CODE_BLOCK_SIZE as usize + 32];
    vbuf[0..4].copy_from_slice(&block_idx.to_le_bytes());
    // SAFETY: ct + meta are within the host-image block.
    unsafe {
        core::ptr::copy_nonoverlapping(ct_ptr, vbuf[4..].as_mut_ptr(), CODE_BLOCK_SIZE as usize);
        core::ptr::copy_nonoverlapping(
            meta_ptr,
            vbuf[4 + CODE_BLOCK_SIZE as usize..].as_mut_ptr(),
            32,
        );
    }
    let mut computed = [0u8; 32];
    crypto.hmac(&hmac_key, &vbuf, &mut computed)?;
    // SAFETY: sig is the 32-byte prefix of the block.
    let stored = unsafe { core::slice::from_raw_parts(sig_ptr, 32) };
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= computed[i] ^ stored[i];
    }
    if diff != 0 {
        return Err(UmbraError::MeasurementMismatch {
            expected: [0; 8],
            got: [0; 8],
        });
    }

    // Evict a victim if installing this block would exceed the cache limit.
    let st = state();
    let resident = st.slots[idx].block_loaded[..st.slots[idx].num_blocks as usize]
        .iter()
        .filter(|&&l| l)
        .count();
    if resident >= CACHE_LIMIT_PER_ENCLAVE {
        if let Some(victim) = find_eviction_victim(idx, block_idx) {
            // SAFETY: victim slot inside the enclave's ESS region.
            unsafe { trap_fill_slot(ESS_BASE + victim * CODE_BLOCK_SIZE) };
            st.slots[idx].block_loaded[victim as usize] = false;
            raw_print::print_str("[UMBRASecureBoot] ESS evict\n");
        }
    }

    // Install: decrypt the ciphertext into its ESS slot, sync I-fetch.
    let enc_key = crypto_impl::derive_enc_key(&mut crypto)?;
    let ess_slot = ESS_BASE + block_idx * CODE_BLOCK_SIZE;
    // SAFETY: block_idx < num_blocks ≤ MAX_EFBS → slot within the ESS region.
    unsafe { install_block(&mut crypto, &enc_key, ct_ptr, ess_slot) };
    fence_i();

    let slot = &mut st.slots[idx];
    slot.block_loaded[block_idx as usize] = true;
    slot.block_counter[block_idx as usize] =
        slot.block_counter[block_idx as usize].saturating_add(1);
    raw_print::print_str("[UMBRASecureBoot] ESS miss -> block loaded\n");
    Ok(())
}

/// Trap-handler hook: is this trap a running enclave fetching from an unloaded
/// (trap-filled) block? An illegal-instruction trap (`mcause == 2`) whose
/// `mepc` lands inside the enclave's ESS code region is an ESS miss — demand-
/// load the faulting block and return `true` so the handler re-executes the now
/// valid instruction (`mepc` is left unchanged). Returns `false` for any other
/// trap (or if the demand-load fails), so the caller falls through to the fault
/// reporter.
pub fn try_handle_ess_miss(frame: &mut TrapFrame) -> bool {
    let st = state();
    let idx = match st.current {
        Some(i) => i,
        None => return false,
    };
    // mcause 2 = illegal instruction (the 0x0000 trap-fill); anything else here
    // is a genuine fault.
    if frame.mcause != 2 {
        return false;
    }
    let slot = &st.slots[idx];
    let lo = ESS_BASE;
    let hi = ESS_BASE + slot.num_blocks * CODE_BLOCK_SIZE;
    if frame.mepc < lo || frame.mepc >= hi {
        return false;
    }
    let block_idx = (frame.mepc - lo) / CODE_BLOCK_SIZE;
    handle_ess_miss(block_idx).is_ok()
}

/// Pick the least-used resident block to evict. Never evicts block 0 (entry) or
/// `keep` (the block being loaded / currently faulting).
fn find_eviction_victim(slot_idx: usize, keep: u32) -> Option<u32> {
    let slot = &state().slots[slot_idx];
    let mut victim: Option<u32> = None;
    let mut best = u32::MAX;
    for b in 1..slot.num_blocks {
        if b == keep || !slot.block_loaded[b as usize] {
            continue;
        }
        let c = slot.block_counter[b as usize];
        if c < best {
            best = c;
            victim = Some(b);
        }
    }
    victim
}
