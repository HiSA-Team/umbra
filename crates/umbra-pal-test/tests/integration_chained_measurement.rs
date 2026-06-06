//! End-to-end sanity test: chained measurement against the host-side
//! SHA-256 stand-in.
//! Mirrors the kernel's `validator::measure` algorithm
//! (init/update-accumulator/update-block/finalize per block) so the
//! kernel and the test harness produce byte-identical digests for any
//! sequence of input blocks.

use umbra_pal_test::{Hash, TestHash};

fn chained_measure<H: Hash>(hasher: &mut H, blocks: &[&[u8]]) -> [u8; 32] {
    let mut accumulator = [0u8; 32];
    for block in blocks {
        hasher.init().unwrap();
        hasher.update(&accumulator).unwrap();
        hasher.update(block).unwrap();
        hasher.finalize(&mut accumulator).unwrap();
    }
    accumulator
}

#[test]
fn chained_measurement_is_deterministic() {
    let mut h1 = TestHash::new();
    let mut h2 = TestHash::new();
    let blocks: &[&[u8]] = &[b"block-1", b"block-2", b"block-3"];
    assert_eq!(
        chained_measure(&mut h1, blocks),
        chained_measure(&mut h2, blocks),
    );
}

#[test]
fn chained_measurement_changes_on_tamper() {
    let mut h = TestHash::new();
    let original: &[&[u8]] = &[b"block-1", b"block-2", b"block-3"];
    let tampered: &[&[u8]] = &[b"block-1", b"BLOCK-2", b"block-3"];
    assert_ne!(
        chained_measure(&mut h, original),
        chained_measure(&mut h, tampered),
    );
}

#[test]
fn empty_input_produces_zero_round() {
    let mut h = TestHash::new();
    let result = chained_measure(&mut h, &[]);
    assert_eq!(result, [0u8; 32]);
}

#[test]
fn single_block_matches_two_step_recompute() {
    let mut h1 = TestHash::new();
    let mut h2 = TestHash::new();
    let single: &[&[u8]] = &[b"only-block"];

    let from_chained = chained_measure(&mut h1, single);

    // Manual re-execution to lock down the algorithm shape:
    // first iteration: hash(zero_accumulator || only-block)
    let mut manual = [0u8; 32];
    h2.init().unwrap();
    h2.update(&manual).unwrap();
    h2.update(b"only-block").unwrap();
    h2.finalize(&mut manual).unwrap();

    assert_eq!(from_chained, manual);
}
