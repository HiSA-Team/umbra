//! Unit tests for the L552 DMA driver.

use super::*;
use umbra_pal_test::mmio::{MmioMem, MmioOp};

/// Count Writes in a log slice — small helper to avoid building an
/// intermediate Vec in this `no_std` crate.
fn count_writes(log: &[MmioOp]) -> usize {
    let mut n = 0;
    for op in log {
        if matches!(op, MmioOp::Write { .. }) {
            n += 1;
        }
    }
    n
}

/// Walk `log` and assert that the i-th Write matches `(want_addr,
/// want_val)`. Reads in between are ignored — only the Write recipe
/// is load-bearing for the DMA HW state machine.
fn assert_nth_write(log: &[MmioOp], n: usize, want_addr: u32, want_val: u32, name: &str) {
    let mut seen = 0;
    for op in log {
        if let MmioOp::Write { addr, value } = *op {
            if seen == n {
                assert_eq!(addr, want_addr, "{name}: addr");
                assert_eq!(value, want_val, "{name}: value");
                return;
            }
            seen += 1;
        }
    }
    panic!("{name}: log only contains {seen} writes, wanted index {n}");
}

/// Return the value of the n-th Write in `log` (regardless of address).
fn nth_write_value(log: &[MmioOp], n: usize) -> (u32, u32) {
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

/// Verifies that `enqueue` emits the CCR-EN-last register-write recipe
/// for a known Request. The DMA HW state machine triggers on CCR.EN,
/// so NDTR / PAR / MAR0 / MAR1 MUST land before the CCR write — this
/// test pins that ordering so a future refactor cannot accidentally
/// reorder them.
#[test]
fn enqueue_emits_ccr_en_last_write_sequence() {
    let dma1_mem = MmioMem::new(DMA1_BASE_ADDR);
    let dma2_mem = MmioMem::new(DMA2_BASE_ADDR);
    let mut dma = Dma::<_>::new_with_mmio(dma1_mem.handle(), dma2_mem.handle());

    // mem2mem Request — channel 0 is free (CCR reads 0 by default).
    let mut req = Request::new();
    req.count = 4;
    req.cpar = 0x2000_1000;
    req.cm0ar = 0x2000_2000;
    req.cm1ar = 0;
    req.mem2mem = true;
    req.minc = true;
    req.pinc = true;
    req.dir = true;
    // SECM + PRIV must be set per the file-header comment ("must be fixed
    // to 1"). Request derives Default which sets all bools to false, so
    // every caller must opt in explicitly; pin that contract here.
    req.secm = true;
    req.priv_ = true;

    let nonce = dma.enqueue(&req);
    assert!(nonce.is_some());

    let log = dma1_mem.write_log();

    // Expected (channel 0) Write recipe, in order:
    // [0] IFCR ← 0xF (clear interrupts for ch 0)
    // [1] CNDTR ← request.count
    // [2] CPAR ← request.cpar
    // [3] CM0AR ← request.cm0ar
    // [4] CM1AR ← request.cm1ar
    // [5] CCR ← new_ccr (with EN bit 0 set) ← MUST be last
    assert_eq!(
        count_writes(&log),
        6,
        "expected 6 writes, got log = {:?}",
        log
    );

    assert_nth_write(&log, 0, DMA1_BASE_ADDR + DMA_IFCR_BASE_OFFSET, 0xF, "IFCR");
    assert_nth_write(
        &log,
        1,
        DMA1_BASE_ADDR + dma_cndtrx_offset(0),
        req.count,
        "CNDTR0",
    );
    assert_nth_write(
        &log,
        2,
        DMA1_BASE_ADDR + dma_cparx_offset(0),
        req.cpar,
        "CPAR0",
    );
    assert_nth_write(
        &log,
        3,
        DMA1_BASE_ADDR + dma_cm0arx_offset(0),
        req.cm0ar,
        "CM0AR0",
    );
    assert_nth_write(
        &log,
        4,
        DMA1_BASE_ADDR + dma_cm1arx_offset(0),
        req.cm1ar,
        "CM1AR0",
    );

    // CCR is the LAST write — verify the address AND that the right
    // CCR bits land. EN (bit 0) must be set so the channel triggers.
    let (ccr_addr, ccr_val) = nth_write_value(&log, 5);
    assert_eq!(ccr_addr, DMA1_BASE_ADDR + dma_ccrx_offset(0), "CCR addr");
    assert_eq!(ccr_val & 1, 1, "CCR.EN must be set");
    assert_eq!((ccr_val >> 14) & 1, 1, "CCR.MEM2MEM must be set");
    assert_eq!((ccr_val >> 7) & 1, 1, "CCR.MINC must be set");
    assert_eq!((ccr_val >> 6) & 1, 1, "CCR.PINC must be set");
    assert_eq!((ccr_val >> 4) & 1, 1, "CCR.DIR must be set");
    assert_eq!(
        (ccr_val >> 17) & 1,
        1,
        "CCR.SECM must be set (default secm=true)"
    );
    assert_eq!(
        (ccr_val >> 20) & 1,
        1,
        "CCR.PRIV must be set (default priv_=true)"
    );
}

/// Verifies that `reserve_ch` flips the internal bitmap and that
/// `release_channel` keeps the channel reserved AND emits the
/// disable-EN-then-clear-SECM write recipe. This pins the
/// reserve/release lock semantics described in the file-header comment.
#[test]
fn reserve_and_release_channel_round_trip_state() {
    let dma1_mem = MmioMem::new(DMA1_BASE_ADDR);
    let dma2_mem = MmioMem::new(DMA2_BASE_ADDR);
    let mut dma = Dma::<_>::new_with_mmio(dma1_mem.handle(), dma2_mem.handle());

    // Initially channel 3 on DMA1 is free.
    assert!(dma.is_ch_free(0, 3), "ch 3 should start free");
    assert!(!dma.is_channel_reserved(0, 3));

    // Reserve it → internal bitmap bit 3 set; is_ch_free now false.
    dma.reserve_ch(0, 3);
    assert!(dma.is_channel_reserved(0, 3));
    assert!(!dma.is_ch_free(0, 3), "reserved channel must not be free");

    // Snapshot how many writes the recorder has seen so we can scope the
    // assertions below to just the release_channel writes.
    let pre_release_writes = count_writes(&dma1_mem.write_log());

    // Release channel 5 (different from 3 to keep the recipe scoped).
    dma.release_channel(0, 5);

    let log = dma1_mem.write_log();

    // Expected release recipe (CCR of channel 5):
    // Read CCR
    // Write CCR with EN cleared
    // Write CCR with EN + SECM cleared
    // → 2 new Writes after release_channel.
    assert_eq!(
        count_writes(&log),
        pre_release_writes + 2,
        "release_channel must emit exactly 2 Writes, log = {:?}",
        log
    );

    // Both new Writes target CCR of channel 5 and have EN cleared.
    let (w0_addr, w0_val) = nth_write_value(&log, pre_release_writes);
    let (w1_addr, w1_val) = nth_write_value(&log, pre_release_writes + 1);
    let ccr5 = DMA1_BASE_ADDR + dma_ccrx_offset(5);
    assert_eq!(
        w0_addr, ccr5,
        "first release Write must target CCR of channel 5"
    );
    assert_eq!(
        w1_addr, ccr5,
        "second release Write must target CCR of channel 5"
    );
    assert_eq!(w0_val & 1, 0, "first release Write must clear CCR.EN");
    assert_eq!(
        w1_val & 1,
        0,
        "second release Write must keep CCR.EN cleared"
    );
    // The second Write additionally clears SECM (bit 17). On real L5
    // silicon this write is a no-op (the bit is RESERVED — see file
    // header) but the driver issues it to match the RM0438 release
    // sequence verbatim.
    assert_eq!(
        (w1_val >> 17) & 1,
        0,
        "second release Write must clear CCR.SECM"
    );

    // And channel 5 is now reserved.
    assert!(dma.is_channel_reserved(0, 5));
}

/// Sanity check the pure-SW `CpuDmaCopier` — exercises the
/// `umbra_hal::Dma` trait surface without touching MMIO. `CpuDmaCopier`
/// is deliberately NOT generic over `MmioAccess` (it does not touch
/// peripheral registers).
#[test]
fn cpu_dma_copier_copies_bytes() {
    use umbra_hal::Dma as _;
    let mut copier = CpuDmaCopier::new();
    let src: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut dst: [u8; 8] = [0; 8];
    copier
        .copy(src.as_ptr() as usize, dst.as_mut_ptr() as usize, src.len())
        .expect("copy must succeed");
    assert_eq!(dst, src);
}
