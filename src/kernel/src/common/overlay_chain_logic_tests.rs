//! Host-side tests for the overlay chain state machine (sibling-file pattern).

use super::*;

#[test]
fn rotated_order_wraps() {
    // k=5, no hot: positions 1..7 visit 6,7,0,1,2,3,4
    let visits: [u8; 7] = core::array::from_fn(|i| chunk_at_skip(5, NO_HOT, (i + 1) as u8));
    assert_eq!(visits, [6, 7, 0, 1, 2, 3, 4]);
    // k=0, no hot: straight order
    let visits: [u8; 7] = core::array::from_fn(|i| chunk_at_skip(0, NO_HOT, (i + 1) as u8));
    assert_eq!(visits, [1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn rotated_order_skips_hot() {
    // k=0 hot=2: 1,3,4,5,6,7 (6 chunks)
    let visits: [u8; 6] = core::array::from_fn(|i| chunk_at_skip(0, 2, (i + 1) as u8));
    assert_eq!(visits, [1, 3, 4, 5, 6, 7]);
    // k=2 hot=7 (wrap case): 3,4,5,6,0,1
    let visits: [u8; 6] = core::array::from_fn(|i| chunk_at_skip(2, 7, (i + 1) as u8));
    assert_eq!(visits, [3, 4, 5, 6, 0, 1]);
    // past the end -> NUM_CHUNKS sentinel
    assert_eq!(chunk_at_skip(0, 2, 7), NUM_CHUNKS);
    assert_eq!(chunk_at_skip(0, NO_HOT, 8), NUM_CHUNKS);
}

#[test]
fn chain_len_accounts_for_hot() {
    assert_eq!(chain_len(0, NO_HOT), 7);
    assert_eq!(chain_len(3, 3), 7); // hot == k degenerates to no-hot
    assert_eq!(chain_len(0, 2), 6);
}

#[test]
fn xfer_sequence_alternates_evict_then_restore() {
    assert_eq!(xfer_at(2, NO_HOT, 1, true), Some(Xfer::Evict(3)));
    assert_eq!(xfer_at(2, NO_HOT, 1, false), Some(Xfer::Restore(3)));
    assert_eq!(xfer_at(2, NO_HOT, 2, true), Some(Xfer::Evict(4)));
    // hot skipped: k=0 hot=1 -> first chain chunk is 2
    assert_eq!(xfer_at(0, 1, 1, true), Some(Xfer::Evict(2)));
    // pos 0 is the sync-prefix chunk (never a background transfer)
    assert_eq!(xfer_at(2, NO_HOT, 0, true), None);
    // complete
    assert_eq!(xfer_at(2, NO_HOT, 8, true), None);
    assert_eq!(xfer_at(0, 2, 7, true), None); // hot shortens the chain
}

#[test]
fn advance_walks_evict_restore_pairs() {
    assert_eq!(advance(1, true), (1, false)); // evict done -> restore same chunk
    assert_eq!(advance(1, false), (2, true)); // restore done -> next chunk's evict
    assert_eq!(advance(7, false), (8, true)); // last restore -> complete
}

#[test]
fn revealed_hi_grows_and_stops_at_top_chunk() {
    // k=2, no hot: restored count = pos-1; straight run above k is chunks 3..7
    assert_eq!(revealed_hi(2, NO_HOT, 1), 2); // nothing restored yet, only k revealed
    assert_eq!(revealed_hi(2, NO_HOT, 2), 3);
    assert_eq!(revealed_hi(2, NO_HOT, 6), 7);
    assert_eq!(revealed_hi(2, NO_HOT, 7), 7); // wrapped chunks never grow the contiguous range
    assert_eq!(revealed_hi(2, NO_HOT, 8), 7);
}

#[test]
fn revealed_hi_passes_through_hot() {
    // k=0 hot=1: with nothing delivered, hot extends the run to 1
    assert_eq!(revealed_hi(0, 1, 1), 1);
    // one delivered (chunk 2, since hot=1 is skipped by the chain): run = 0,1(hot),2
    assert_eq!(revealed_hi(0, 1, 2), 2);
    // k=0 hot=3: one delivered (chunk 1) -> run stops before 2
    assert_eq!(revealed_hi(0, 3, 2), 1);
    // two delivered (1,2) -> passes through hot 3 -> hi=3
    assert_eq!(revealed_hi(0, 3, 3), 3);
    // three delivered (1,2,4) -> hi=4
    assert_eq!(revealed_hi(0, 3, 4), 4);
}

#[test]
fn revealed_hi_edges() {
    assert_eq!(revealed_hi(0, NO_HOT, 8), 7); // k=0: full straight growth
    assert_eq!(revealed_hi(7, NO_HOT, 1), 7); // k=7: already at top, never grows
    assert_eq!(revealed_hi(7, NO_HOT, 5), 7);
}

#[test]
fn completion() {
    assert!(!is_complete(0, NO_HOT, 7));
    assert!(is_complete(0, NO_HOT, 8));
    // hot shortens the chain by one pair
    assert!(!is_complete(0, 2, 6));
    assert!(is_complete(0, 2, 7));
}

#[test]
fn chunk_of_maps_window_addresses() {
    const BASE: u32 = 0x340E_0000;
    assert_eq!(chunk_of(BASE, BASE), Some(0));
    assert_eq!(chunk_of(BASE + 2047, BASE), Some(0));
    assert_eq!(chunk_of(BASE + 2048, BASE), Some(1));
    assert_eq!(chunk_of(BASE + 16383, BASE), Some(7));
    assert_eq!(chunk_of(BASE + 16384, BASE), None);
    assert_eq!(chunk_of(BASE - 4, BASE), None);
}
