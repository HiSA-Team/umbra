//! Unit tests for the L552 HASH driver.

use super::*;
use umbra_pal_test::mmio::{MmioMem, MmioOp};

/// Return the value of the n-th Write in `log` (regardless of address).
fn nth_write(log: &[MmioOp], n: usize) -> (u32, u32) {
    let mut seen = 0;
    for op in log {
        if let MmioOp::Write { addr, value } = *op {
            if seen == n {
                return (addr, value);
            }
            seen += 1;
        }
    }
    panic!("log only contains {seen} writes, wanted index {n}");
}

/// Returns the value of the most-recent Write to `want_addr`. Useful for
/// the algorithm-select sequence where `set_bit` / `clear_bit` issue a
/// read-modify-write pair against CR repeatedly.
fn last_write_to(log: &[MmioOp], want_addr: u32) -> Option<u32> {
    let mut found = None;
    for op in log {
        if let MmioOp::Write { addr, value } = *op {
            if addr == want_addr {
                found = Some(value);
            }
        }
    }
    found
}

/// Verifies that `Hash::start(SHA256, Width8, None)` writes the right
/// CR encoding: ALGO0 (bit 7) set, ALGO1 (bit 18) set, MODE (bit 6)
/// cleared (no HMAC), DATATYPE (bits 5:4) = 10b (Width8), INIT (bit 2)
/// set. This pins the HASH state-machine register-write order without
/// requiring real silicon. The DINIS bit (SR bit 0) is preloaded so
/// `store_context`'s busy-loop returns immediately.
#[test]
fn start_sha256_width8_no_hmac_writes_expected_cr() {
    let mem = MmioMem::new(HASH_BASE_ADDR);
    // SR.DINIS = 1 so the `loop {... }` in `store_context` exits.
    mem.preload_register(HASH_SR_BASE_OFFSET, 1);

    let mut hash = Hash::<_>::new_with_mmio(mem.handle());
    let _ctx = hash
        .start(Algorithm::SHA256, DataType::Width8, None)
        .unwrap();

    let log = mem.write_log();
    let cr_addr = HASH_BASE_ADDR + HASH_CR_BASE_OFFSET;

    // After all CR read-modify-writes have happened, the latest CR
    // value seen by the mem must encode: DATATYPE = 10b (Width8) at
    // bits 5:4, ALGO0 (bit 7) = 1, ALGO1 (bit 18) = 1, MODE (bit 6) = 0,
    // INIT (bit 2) = 1.
    let final_cr = last_write_to(&log, cr_addr).expect("start() must write CR at least once");
    assert_eq!(
        (final_cr >> 4) & 0b11,
        0b10,
        "CR.DATATYPE must be Width8 (10b)"
    );
    assert_eq!((final_cr >> 7) & 1, 1, "CR.ALGO0 must be set for SHA256");
    assert_eq!((final_cr >> 18) & 1, 1, "CR.ALGO1 must be set for SHA256");
    assert_eq!(
        (final_cr >> 6) & 1,
        0,
        "CR.MODE must be cleared (no HMAC key)"
    );
    assert_eq!((final_cr >> 2) & 1, 1, "CR.INIT must be set");
}

/// Verifies that `finish` reads HR0–HR4 at the contiguous bank
/// (HASH_HR_BASE_OFFSET) and HR5–HR7 at the **split bank**
/// (HASH_HR5_BASE_OFFSET = 0x324). This is the landmine documented in
/// `project_umbra_drivers_crypto`: misreading HR5–HR7 yields correct
/// first-160 bits + garbage last-96.
/// We preload distinct sentinel values into each HR slot, run finish()
/// on an empty context, and assert the digest bytes match the BE
/// representation of each sentinel — which only happens if the driver
/// reads from the right offsets.
#[test]
fn finish_reads_hr5_hr6_hr7_from_split_bank_offsets() {
    let mem = MmioMem::new(HASH_BASE_ADDR);
    // Preload SR so both `store_context`'s DINIS wait AND finish's
    // DCIS wait return immediately. DINIS = bit 0, DCIS = bit 1.
    mem.preload_register(HASH_SR_BASE_OFFSET, 0b11);

    // Preload HR0–HR4 at the contiguous bank.
    for i in 0..5u32 {
        mem.preload_register(HASH_HR_BASE_OFFSET + i * 4, 0xAA00_0000 | i);
    }
    // Preload HR5/HR6/HR7 at the split bank (0x324/0x328/0x32C). If
    // the driver reads HR5–HR7 from `HR_BASE + 5*4` (== 0x20, which is
    // IMR!) the test will fail — that's exactly the landmine.
    mem.preload_register(HASH_HR5_BASE_OFFSET + 0, 0xBB00_0005);
    mem.preload_register(HASH_HR5_BASE_OFFSET + 4, 0xBB00_0006);
    mem.preload_register(HASH_HR5_BASE_OFFSET + 8, 0xBB00_0007);

    let mut hash = Hash::<_>::new_with_mmio(mem.handle());
    // Build a context with `first_word_sent = true` so finish() takes
    // the no-leftover path and goes straight to DCAL + HR readout.
    let mut ctx = hash
        .start(Algorithm::SHA256, DataType::Width8, None)
        .unwrap();
    ctx.first_word_sent = true;
    ctx.buflen = 0;

    let mut digest = [0u8; 32];
    let n = hash.finish(ctx, &mut digest).unwrap();
    assert_eq!(n, 32, "SHA-256 digest is 32 bytes");

    // HR0..HR4 → digest[0..20]
    for i in 0..5u32 {
        let want = (0xAA00_0000u32 | i).to_be_bytes();
        let start = (i as usize) * 4;
        assert_eq!(
            &digest[start..start + 4],
            &want,
            "HR{} (contiguous bank) byte mismatch",
            i
        );
    }
    // HR5..HR7 → digest[20..32] — MUST come from the split bank.
    assert_eq!(
        &digest[20..24],
        &0xBB00_0005u32.to_be_bytes(),
        "HR5 (split bank @ 0x324)"
    );
    assert_eq!(
        &digest[24..28],
        &0xBB00_0006u32.to_be_bytes(),
        "HR6 (split bank @ 0x328)"
    );
    assert_eq!(
        &digest[28..32],
        &0xBB00_0007u32.to_be_bytes(),
        "HR7 (split bank @ 0x32C)"
    );
}

/// Sanity check the `Sha256Engine::from_hash` adapter wiring — confirms
/// the generic propagates from `Hash<M>` through `Sha256Engine<M>` and
/// `inner_mut` returns a mutable borrow at the same concrete type.
/// Pure construction test; does not invoke the trait surface (which
/// would need a full DCAL round-trip mem).
#[test]
fn sha256_engine_from_hash_preserves_mmio_backend() {
    let mem = MmioMem::new(HASH_BASE_ADDR);
    let hw = Hash::<_>::new_with_mmio(mem.handle());
    let mut engine = Sha256Engine::from_hash(hw);

    // Type assertion: inner_mut returns &mut Hash<M> where M = MmioHandle.
    let inner: &mut Hash<_> = engine.inner_mut();
    // Touch the inner driver so the type isn't dead — write CR via the
    // mem and confirm the log captures it.
    inner.mmio.write(HASH_CR_BASE_OFFSET, 0xDEAD_BEEF);

    let log = mem.write_log();
    let (addr, value) = nth_write(&log, 0);
    assert_eq!(addr, HASH_BASE_ADDR + HASH_CR_BASE_OFFSET);
    assert_eq!(value, 0xDEAD_BEEF);
}
