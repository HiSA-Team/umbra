//! Pure state machine for the N657 inter-enclave overlay async switch chain.
//! No MMIO — host-tested. The boot crate's `overlay_chain` module drives HPDMA1/MPU
//! from these functions. Chunk `k` (the incoming enclave's resume-PC chunk) is moved
//! synchronously at switch time; positions 1..NUM_CHUNKS walk the remaining chunks in
//! rotated order, each as an Evict(A)-then-Restore(B) pair, one DMA transfer in flight.

pub const NUM_CHUNKS: u8 = 8;
pub const CHUNK_BYTES: u32 = 2048;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Xfer {
    /// Copy outgoing enclave's chunk `.0`: window -> its backing.
    Evict(u8),
    /// Copy incoming enclave's chunk `.0`: its backing -> window.
    Restore(u8),
}

/// Sentinel: no hot chunk (first switch of an enclave, or hot == k).
pub const NO_HOT: u8 = 0xFF;

/// Chunk index visited at rotated position `pos` (position 0 = the sync-prefix chunk k).
pub fn chunk_at(k: u8, pos: u8) -> u8 {
    (k + pos) % NUM_CHUNKS
}

/// The pos-th chunk (1-based) of the background chain: rotated order k+1..k-1 (wrap),
/// skipping `hot` (pre-restored + revealed in the sync prefix; the chain must neither
/// re-transfer it — the enclave is writing there — nor count it). `NO_HOT` skips nothing.
/// Returns NUM_CHUNKS (invalid chunk) past the end of the chain.
pub fn chunk_at_skip(k: u8, hot: u8, pos: u8) -> u8 {
    let mut seen = 0;
    let mut i = 1;
    while i < NUM_CHUNKS {
        let c = chunk_at(k, i);
        if c != hot {
            seen += 1;
            if seen == pos {
                return c;
            }
        }
        i += 1;
    }
    NUM_CHUNKS
}

/// Number of chunk pairs the background chain carries.
pub fn chain_len(k: u8, hot: u8) -> u8 {
    if hot == NO_HOT || hot == k {
        NUM_CHUNKS - 1
    } else {
        NUM_CHUNKS - 2
    }
}

/// The transfer to run at (pos, phase). None when pos is 0 (sync prefix, not part of the
/// background chain) or past the chain length (complete).
pub fn xfer_at(k: u8, hot: u8, pos: u8, evict_phase: bool) -> Option<Xfer> {
    if pos == 0 || pos > chain_len(k, hot) {
        return None;
    }
    let c = chunk_at_skip(k, hot, pos);
    if c >= NUM_CHUNKS {
        return None;
    }
    Some(if evict_phase { Xfer::Evict(c) } else { Xfer::Restore(c) })
}

/// Next (pos, evict_phase) after the current transfer completes.
pub fn advance(pos: u8, evict_phase: bool) -> (u8, bool) {
    if evict_phase {
        (pos, false)
    } else {
        (pos + 1, true)
    }
}

/// Highest chunk index revealed contiguously from k: delivered chunks extend the run;
/// `hot` passes through for free (pre-restored + revealed via the hot MPU region);
/// contiguity stops at chunk NUM_CHUNKS-1 — the wrapped chunks (below k) are revealed
/// only by the full reveal at completion. `pos-1` chunks have been delivered in-order.
pub fn revealed_hi(k: u8, hot: u8, pos: u8) -> u8 {
    let mut delivered = pos.saturating_sub(1);
    let mut hi = k;
    let mut c = k + 1;
    while c < NUM_CHUNKS {
        if c == hot {
            hi = c;
            c += 1;
            continue;
        }
        if delivered == 0 {
            break;
        }
        delivered -= 1;
        hi = c;
        c += 1;
    }
    hi
}

pub fn is_complete(k: u8, hot: u8, pos: u8) -> bool {
    pos > chain_len(k, hot)
}

/// Chunk containing `addr`, None outside the window.
pub fn chunk_of(addr: u32, window_base: u32) -> Option<u8> {
    if addr < window_base {
        return None;
    }
    let off = addr - window_base;
    if off >= NUM_CHUNKS as u32 * CHUNK_BYTES {
        return None;
    }
    Some((off / CHUNK_BYTES) as u8)
}

#[cfg(test)]
#[path = "overlay_chain_logic_tests.rs"]
mod tests;
