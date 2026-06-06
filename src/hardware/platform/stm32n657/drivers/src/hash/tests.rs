//! Unit tests for the N657 HASH driver.
//! Split from `hash.rs` to keep the parent file under the 600-LOC hard-cap.

use super::*;
use umbra_pal_test::mmio::{MmioMem, MmioOp};

/// Returns the value of the most-recent Write to `want_addr`. Useful
/// when the driver issues several writes to the same register (e.g.
/// CR is touched once, STR is touched multiple times with different
/// NBLW / DCAL combinations).
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

/// Count the number of Writes in `log` targeting `want_addr`.
fn count_writes_to(log: &[MmioOp], want_addr: u32) -> usize {
    log.iter()
        .filter(|op| matches!(op, MmioOp::Write { addr, .. } if *addr == want_addr))
        .count()
}

/// Verifies that `hmac_sha256` issues the documented N657 CR
/// configuration at the very first write: ALGO[1:0] = 0b11 at bits
/// 17:18 (SHA-256), MODE (bit 6) set (HMAC), DATATYPE (bits 5:4) =
/// 0b10 (byte-swap), INIT (bit 2) set. This is load-bearing for the
/// CJ2 chained-measurement boot path. Misencoding any of these
/// fields silently corrupts every chained hash.
/// Preloads SR with DINIS=1 + DCIS=1 so all four waits exit on the
/// first iteration and the test completes without spinning.
#[test]
fn hmac_sha256_writes_expected_cr_encoding() {
    let mem = MmioMem::new(HASH_BASE_ADDR);
    // Make every busy-loop exit immediately: SR.DINIS=1, SR.DCIS=1.
    mem.preload_register(HASH_SR_OFFSET, SR_DINIS_MASK | SR_DCIS_MASK);

    let mut hash = Hash::<_>::new_with_mmio(mem.handle());
    let key = [0u8; 32];
    let data = [0u8; 16];
    let mut output = [0u8; 32];
    hash.hmac_sha256(&key, &data, &mut output);

    let cr_addr = HASH_BASE_ADDR + HASH_CR_OFFSET;
    let cr_val =
        last_write_to(&mem.write_log(), cr_addr).expect("hmac_sha256 must write CR at least once");

    // ALGO[1:0] = 0b11 at bits 17:18 → SHA-256 (N657 layout).
    assert_eq!(
        (cr_val >> 17) & 0b11,
        0b11,
        "CR.ALGO[1:0] must be 0b11 for SHA-256"
    );
    // MODE (bit 6) = 1 → HMAC mode.
    assert_eq!((cr_val >> 6) & 1, 1, "CR.MODE must be set for HMAC");
    // DATATYPE (bits 5:4) = 0b10 → byte-swap.
    assert_eq!(
        (cr_val >> 4) & 0b11,
        0b10,
        "CR.DATATYPE must be 0b10 (byte-swap)"
    );
    // INIT (bit 2) = 1.
    assert_eq!((cr_val >> 2) & 1, 1, "CR.INIT must be set");
}

/// Verifies the three-stage HMAC pipeline issues exactly six STR
/// writes — NBLW + (NBLW|DCAL) for each of {inner key, message,
/// outer key} — and that every DCAL trigger sets STR bit 8. This
/// pins the register-write order documented in the module doc and
/// guards against accidentally collapsing or reordering DCAL
/// triggers (the HW state machine is sensitive: a missed DCAL
/// silently produces the wrong digest, not a fault).
#[test]
fn hmac_sha256_issues_three_dcal_triggers_in_order() {
    let mem = MmioMem::new(HASH_BASE_ADDR);
    mem.preload_register(HASH_SR_OFFSET, SR_DINIS_MASK | SR_DCIS_MASK);

    let mut hash = Hash::<_>::new_with_mmio(mem.handle());
    // key len = 32 (multiple of 4) → key_nblw = 0
    // data len = 16 (multiple of 4) → nblw = 0
    let key = [0u8; 32];
    let data = [0u8; 16];
    let mut output = [0u8; 32];
    hash.hmac_sha256(&key, &data, &mut output);

    let str_addr = HASH_BASE_ADDR + HASH_STR_OFFSET;
    let log = mem.write_log();
    // Expect exactly 6 STR writes: 2 per stage × 3 stages.
    assert_eq!(
        count_writes_to(&log, str_addr),
        6,
        "expected 6 STR writes (NBLW + NBLW|DCAL per stage × 3 stages)"
    );

    // Walk STR writes in order. For aligned key/data, even-index
    // STR writes set NBLW=0 with DCAL clear, odd-index writes set
    // DCAL (bit 8) high.
    let mut seen_str: usize = 0;
    for op in log.iter() {
        if let MmioOp::Write { addr, value } = *op {
            if addr != str_addr {
                continue;
            }
            let dcal_bit = (value >> STR_DCAL_BIT) & 1;
            if seen_str % 2 == 0 {
                assert_eq!(
                    dcal_bit, 0,
                    "STR write #{seen_str} should NOT have DCAL set yet"
                );
            } else {
                assert_eq!(dcal_bit, 1, "STR write #{seen_str} should trigger DCAL");
            }
            seen_str += 1;
        }
    }
    assert_eq!(seen_str, 6, "expected to walk 6 STR writes");
}

/// Verifies `hmac_sha256` reads HR0..HR4 at the contiguous bank
/// (HASH_HR_OFFSET=0x0C) and HR5..HR7 at the **split bank**
/// (HASH_HR5_OFFSET=0x324) — the same landmine the L552 driver has
/// (see module doc § register map). Misreading HR5..HR7 yields the
/// correct first 160 bits + garbage for the last 96.
/// We preload distinct sentinel values into each HR slot and assert
/// the digest bytes match the BE representation of each sentinel —
/// which only happens if the driver reads from the right offsets.
#[test]
fn hmac_sha256_reads_hr5_hr6_hr7_from_split_bank() {
    let mem = MmioMem::new(HASH_BASE_ADDR);
    mem.preload_register(HASH_SR_OFFSET, SR_DINIS_MASK | SR_DCIS_MASK);

    // Preload HR0..HR4 at contiguous bank (0x0C..0x1C).
    for i in 0..5u32 {
        mem.preload_register(HASH_HR_OFFSET + i * 4, 0xAA00_0000 | i);
    }
    // Preload HR5/HR6/HR7 at split bank (0x324/0x328/0x32C). If the
    // driver were to read HR5..HR7 from `HR_BASE + 5*4 = 0x20` (the
    // SR field area), the test would fail — that's exactly the
    // landmine being guarded against.
    mem.preload_register(HASH_HR5_OFFSET + 0, 0xBB00_0005);
    mem.preload_register(HASH_HR5_OFFSET + 4, 0xBB00_0006);
    mem.preload_register(HASH_HR5_OFFSET + 8, 0xBB00_0007);

    let mut hash = Hash::<_>::new_with_mmio(mem.handle());
    let key = [0u8; 32];
    let data = [0u8; 16];
    let mut digest = [0u8; 32];
    hash.hmac_sha256(&key, &data, &mut digest);

    // HR0..HR4 → digest[0..20]
    for i in 0..5u32 {
        let want = (0xAA00_0000u32 | i).to_be_bytes();
        let start = (i as usize) * 4;
        assert_eq!(
            &digest[start..start + 4],
            &want,
            "HR{i} (contiguous bank @ 0x{:X}) byte mismatch",
            HASH_HR_OFFSET + i * 4,
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

/// Sanity check the `Sha256Engine` SW path still computes a correct
/// SHA-256 digest (NIST FIPS-180 test vector: empty string). The SW
/// `Sha256` was not migrated to MMIO (it does pure-software SHA-256
/// per `project_n657_rifsc_blocked`); this test guards against
/// regressions in the K-constant table + compress function during
/// the round-6 refactor.
#[test]
fn sha256_engine_empty_string_matches_fips180_vector() {
    use umbra_hal::Hash as HashTrait;
    let mut engine = Sha256Engine::<RealMmio>::new();
    engine.init().unwrap();
    // Empty input → 0 update calls.
    let mut digest = [0u8; 32];
    engine.finalize(&mut digest).unwrap();
    // SHA-256("") from FIPS-180-4 §B.1.
    let want: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(digest, want, "SW SHA-256 empty-string digest mismatch");
}
