//! Speculative non-blocking overlay switch (default transport of `interenclave_overlay`).
//!
//! `begin_switch` moves ONLY the chunk containing the incoming enclave's resume PC
//! synchronously (~2 KB evict + 2 KB restore), rotates MPU region 5 to reveal just that
//! chunk, and returns — the asm resumes enclave B immediately. The remaining 7 chunk
//! pairs travel in the background on HPDMA1 ch2 in rotated order k+1..7,0..k-1: the TC
//! IRQ (70, prio 0x80) chains the next transfer and pends PendSV after each restored
//! chunk; PendSV (0xE0) does the cache maintenance and grows region 5's limit while the
//! revealed range is contiguous from k. If B touches a hidden chunk first, MemManage
//! recovers via `on_fault` -> `drain()` (abort + bounded synchronous completion — never
//! waits on PendSV-posted state, the proven anti-deadlock rule from `async_ess`).
//!
//! Concurrency model (single core, priority-ordered): SysTick/SVC (0x40) and faults
//! preempt the TC IRQ (0x80), which preempts PendSV (0xE0), which preempts only the
//! unprivileged enclave. `ACTIVE` is claimed with an atomic swap by whichever closer
//! (PendSV completion, fault, drain) fires first; the losers are no-ops. A stale TC IRQ
//! or PendSV after close falls through to the prefetch-engine seams, which no-op on
//! empty state. `drain()` flips ACTIVE=false FIRST and then drops the latched NVIC
//! pending bit for the ch2 TC IRQ, so cold-path (thread-mode) drains cannot race the
//! TC IRQ — neither a live one (ACTIVE gate) nor a stale latch (which would otherwise
//! fall through to `prefetch::on_dma_complete` and clear the flags the sync copies poll).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use arm::mmio::{ICIALLU, MPU_RBAR, MPU_RLAR, MPU_RNR};
use kernel::common::ess::ESS_BASE;
use kernel::common::overlay_chain_logic as logic;

const CH: u8 = 2; // shared with the prefetch engine; the chain owns it while ACTIVE
const NVIC_ICPR2: u32 = 0xE000_E288; // IRQ 64..95 clear-pending (see prefetch.rs nvic_setup)
const NVIC_ISER2: u32 = 0xE000_E108; // IRQ 64..95 set-enable
const HPDMA_CH2_IRQ_BIT: u32 = 1 << (70 - 64); // HPDMA1 ch2 TC = IRQ 70
const CB: u32 = logic::CHUNK_BYTES;
const WINDOW_BYTES: u32 = logic::NUM_CHUNKS as u32 * CB; // 16 KB
const DMA_BUDGET: u32 = 8_000_000;
const RBAR_RW_EXEC: u32 = 0b01 << 1; // AP=RW any privilege, XN=0 — matches api_impl region 5

static ACTIVE: AtomicBool = AtomicBool::new(false);
static K: AtomicU32 = AtomicU32::new(0);
static POS: AtomicU32 = AtomicU32::new(0);
static EVICT_PHASE: AtomicBool = AtomicBool::new(true);
static OUT_SLOT: AtomicU32 = AtomicU32::new(0);
static IN_SLOT: AtomicU32 = AtomicU32::new(0);
static FULL_BASE: AtomicU32 = AtomicU32::new(0);
static FULL_LIMIT: AtomicU32 = AtomicU32::new(0);
static REVEALED_HI: AtomicU32 = AtomicU32::new(0);
/// The active chain's hot chunk (logic::NO_HOT as u32 when none).
static HOT: AtomicU32 = AtomicU32::new(logic::NO_HOT as u32);
/// Learned per-slot hot data chunk: the chunk each enclave faults on right after resume
/// (its working-set globals — HW-measured to be static per enclave). Recorded by
/// `on_fault`, consumed by the next `begin_switch` of that slot.
static HOT_FOR_SLOT: [AtomicU32; 2] = [
    AtomicU32::new(logic::NO_HOT as u32),
    AtomicU32::new(logic::NO_HOT as u32),
];
/// MPU region dedicated to the hot chunk's reveal (regions 3-9 are in use, DREGION=16).
const HOT_REGION: u32 = 10;
// HOT_FOR_SLOT is indexed `& 1`; it must cover every overlay slot. The overlay backings
// (prefetch::overlay) are the authority on slot count — keep them in lockstep.
const _: () = assert!(crate::prefetch::overlay::NUM_SLOTS == 2);

/// Chains that completed silently in the background (the speculation paid).
pub static CHAIN_HITS: AtomicU32 = AtomicU32::new(0);
/// Chains completed by the MemManage fallback (B outran the DMA).
pub static CHAIN_FAULTS: AtomicU32 = AtomicU32::new(0);
/// Chains force-completed by `drain()` (next switch / cold path / checkpoint).
pub static CHAIN_DRAINS: AtomicU32 = AtomicU32::new(0);

fn chunk_base(c: u8) -> u32 {
    ESS_BASE + c as u32 * CB
}

fn backing_chunk(slot: u32, c: u8) -> u32 {
    crate::prefetch::overlay::backing_addr(slot as usize) + c as u32 * CB
}


fn xfer_src_dst(x: logic::Xfer) -> (u32, u32) {
    match x {
        logic::Xfer::Evict(c) => (chunk_base(c), backing_chunk(OUT_SLOT.load(Ordering::SeqCst), c)),
        logic::Xfer::Restore(c) => (backing_chunk(IN_SLOT.load(Ordering::SeqCst), c), chunk_base(c)),
    }
}

/// MPU region reprogram. LANDMINE: MPU_RNR is shared state — a higher-priority
/// exception (SysTick reconfiguring region 4) preempting between the RNR and RBAR
/// writes would corrupt the wrong region. Mask IRQs around the triplet.
fn set_region(n: u32, base: u32, limit: u32) {
    // SAFETY: device registers, single core; PRIMASK save/restore around the triplet.
    unsafe {
        let primask: u32;
        core::arch::asm!("mrs {}, PRIMASK", "cpsid i", out(reg) primask);
        core::ptr::write_volatile(MPU_RNR, n);
        core::ptr::write_volatile(MPU_RBAR, (base & 0xFFFF_FFE0) | RBAR_RW_EXEC);
        core::ptr::write_volatile(MPU_RLAR, (limit & 0xFFFF_FFE0) | 0x01);
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
        if primask & 1 == 0 {
            core::arch::asm!("cpsie i");
        }
    }
}

fn set_region5(base: u32, limit: u32) {
    set_region(5, base, limit);
}

/// Disable an MPU region (RLAR.EN=0). Same RNR critical section as `set_region`.
fn disable_region(n: u32) {
    // SAFETY: device registers, single core; PRIMASK save/restore around the pair.
    unsafe {
        let primask: u32;
        core::arch::asm!("mrs {}, PRIMASK", "cpsid i", out(reg) primask);
        core::ptr::write_volatile(MPU_RNR, n);
        core::ptr::write_volatile(MPU_RLAR, 0);
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
        if primask & 1 == 0 {
            core::arch::asm!("cpsie i");
        }
    }
}

/// Full reveal: region 5 back to the whole extent. The hot region MUST drop first —
/// ARMv8-M faults an access matching two enabled regions, so region 10 can never stay
/// enabled while region 5 covers the hot chunk.
fn reveal_full() {
    disable_region(HOT_REGION);
    set_region5(FULL_BASE.load(Ordering::SeqCst), FULL_LIMIT.load(Ordering::SeqCst));
}

/// Invalidate the D-cache lines of chunks lo..=hi, skipping `skip` (the hot chunk: the
/// enclave has been writing there since the prefix — invalidating it would rewind it).
fn invalidate_chunks(lo: u8, hi: u8, skip: u8) {
    let mut c = lo;
    while c <= hi && c < logic::NUM_CHUNKS {
        if c != skip {
            drivers::hpdma::dcache_invalidate_range(chunk_base(c) as usize, CB as usize);
        }
        c += 1;
    }
}

fn dma_copy_sync(src: u32, dst: u32, len: u32) {
    let dma = drivers::hpdma::Hpdma1::new();
    dma.reset_channel(CH);
    dma.configure_mem_to_mem(CH, src, dst, len);
    dma.enable_channel(CH);
    let sr = dma.wait_complete(CH, DMA_BUDGET);
    dma.clear_flags(CH);
    // `wait_complete` returns the final CxSR word: TCF (CH_TCF) on success, an error
    // flag or a TCF-less word on timeout. Revealing after a failed copy would let the
    // enclave execute stale bytes with no fault — halt instead (panic policy).
    if sr & drivers::hpdma::CH_TCF == 0 {
        crate::raw_print::print_str("[OVL] FATAL: sync DMA timeout dst=0x");
        crate::raw_print::print_hex(dst);
        crate::raw_print::print_str("\r\n");
        kernel::common::panic_policy::handle_fault();
    }
}

fn kick(x: logic::Xfer) {
    let (src, dst) = xfer_src_dst(x);
    let dma = drivers::hpdma::Hpdma1::new();
    dma.reset_channel(CH);
    // Drop any stale NVIC latch from a previous transfer so one physical transfer can
    // never double-fire on_tc_irq (a double-advance would skip a chunk pair).
    // SAFETY: NVIC ICPR write-1-to-clear, single core.
    unsafe {
        core::ptr::write_volatile(NVIC_ICPR2 as *mut u32, HPDMA_CH2_IRQ_BIT);
    }
    dma.start_mem_to_mem_irq(CH, src, dst, CB);
}

fn icache_flush() {
    // SAFETY: I-cache invalidate + barriers so fetches reload DMA-written bytes.
    unsafe {
        core::ptr::write_volatile(ICIALLU, 0);
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
    }
}

/// Start the speculative switch out_slot -> in_slot. Synchronous prefix (chunk k pair)
/// + rotated region-5 reveal + background chain kick; returns immediately so the asm
/// resumes the incoming enclave. Call `overlay_reconfigure_mpu` BEFORE this (it programs
/// region 4 and region 5's full extent; this shrinks region 5 to the rotated reveal).
/// `[code_base, code_limit]` is the incoming enclave's full region-5 extent.
///
/// SAFETY: SysTick/SVC handler context (TC IRQ cannot preempt); slots < NUM_SLOTS;
/// the window and backings are DMA-reachable and chunk-aligned.
pub unsafe fn begin_switch(
    out_slot: usize,
    in_slot: usize,
    resume_pc: u32,
    code_base: u32,
    code_limit: u32,
) {
    drain(); // invariant: at most one live chain (also covers a leftover from a prior switch)

    let k = logic::chunk_of(resume_pc, ESS_BASE).unwrap_or(0);
    // Learned hot data chunk for the incoming enclave (NO_HOT on its first switch, or
    // when it coincides with k — one region suffices then).
    let mut hot = HOT_FOR_SLOT[in_slot & 1].load(Ordering::SeqCst) as u8;
    if hot >= logic::NUM_CHUNKS || hot == k {
        hot = logic::NO_HOT;
    }

    drivers::hpdma::enable_clock();
    let dma = drivers::hpdma::Hpdma1::new();
    dma.set_channel_secure(CH);

    // Commit ALL of A's window once; every later evict DMA reads committed bytes.
    drivers::hpdma::dcache_clean_range(ESS_BASE as usize, WINDOW_BYTES as usize);

    // Sync prefix: the chunk-k pair (evict A[k], restore B[k]) + the hot-chunk pair,
    // + their cache maintenance. ~4-8 KB of DMA instead of the full 32 KB.
    let kb = chunk_base(k);
    dma_copy_sync(kb, backing_chunk(out_slot as u32, k), CB);
    dma_copy_sync(backing_chunk(in_slot as u32, k), kb, CB);
    drivers::hpdma::dcache_invalidate_range(kb as usize, CB as usize);
    if hot != logic::NO_HOT {
        let hb = chunk_base(hot);
        dma_copy_sync(hb, backing_chunk(out_slot as u32, hot), CB);
        dma_copy_sync(backing_chunk(in_slot as u32, hot), hb, CB);
        drivers::hpdma::dcache_invalidate_range(hb as usize, CB as usize);
    }
    icache_flush();

    HOT.store(hot as u32, Ordering::SeqCst);
    K.store(k as u32, Ordering::SeqCst);
    POS.store(1, Ordering::SeqCst);
    EVICT_PHASE.store(true, Ordering::SeqCst);
    OUT_SLOT.store(out_slot as u32, Ordering::SeqCst);
    IN_SLOT.store(in_slot as u32, Ordering::SeqCst);
    FULL_BASE.store(code_base, Ordering::SeqCst);
    FULL_LIMIT.store(code_limit, Ordering::SeqCst);
    REVEALED_HI.store(k as u32, Ordering::SeqCst);

    crate::prefetch::overlay::set_resident(in_slot);
    crate::prefetch::overlay::SWITCHES.fetch_add(1, Ordering::SeqCst);
    ACTIVE.store(true, Ordering::SeqCst);

    // Rotated reveal: only chunk k, clamped to the enclave's region-5 extent.
    let reveal_lo = if code_base > kb { code_base } else { kb };
    let kb_end = kb + CB - 1;
    let reveal_hi = if code_limit < kb_end { code_limit } else { kb_end };
    if reveal_hi < reveal_lo {
        // Degenerate clamp (bogus resume_pc -> k forced to 0 while the extent sits above
        // chunk 0): region 5 would match no address and every switch would eat a full
        // fault+drain. Complete the switch synchronously instead of arming the chain;
        // drain's reveal_full() restores the full [code_base, code_limit] extent.
        drain();
        return;
    }
    set_region5(reveal_lo, reveal_hi);
    // Hot-chunk reveal via the dedicated region (content restored in the prefix above).
    // Clamped to the enclave extent; disabled when there is no hot chunk. Never overlaps
    // region 5 (which covers only chunk k here; growth past the hot chunk disables this
    // region first — see on_pendsv).
    if hot != logic::NO_HOT {
        let hb = chunk_base(hot);
        let hb_end = hb + CB - 1;
        let h_lo = if code_base > hb { code_base } else { hb };
        let h_hi = if code_limit < hb_end { code_limit } else { hb_end };
        if h_hi >= h_lo {
            set_region(HOT_REGION, h_lo, h_hi);
        } else {
            disable_region(HOT_REGION);
        }
    } else {
        disable_region(HOT_REGION);
    }

    #[cfg(feature = "overlay_sync_switch")]
    {
        drain(); // bisection build: complete everything before resuming B
        return;
    }

    #[cfg(not(feature = "overlay_sync_switch"))]
    {
        // Enable the ch2 TC IRQ line in the NVIC. The chain must NOT rely on the boot
        // prefetch self-test's one-shot nvic_setup having left it enabled — that self-test
        // is feature-gated and, even when present, its priority/enable state is not a
        // contract. Without this the TC IRQ never fires under the enclave and every chain
        // stalls at pos=1 until a drain (HW-confirmed: ISER2 bit6 = 0). Idempotent.
        // SAFETY: NVIC ISER write, single core.
        unsafe {
            core::ptr::write_volatile(NVIC_ISER2 as *mut u32, HPDMA_CH2_IRQ_BIT);
        }
        // Kick the background chain: first transfer skips the sync-prefixed chunks.
        if let Some(x) = logic::xfer_at(k, hot, 1, true) {
            kick(x);
        }
    }
}

/// HPDMA1 ch2 TC seam. Returns true if the chain consumed the IRQ. A stale IRQ after a
/// close (ACTIVE=false) returns false and falls through to `prefetch::on_dma_complete`,
/// which clears the flags and pends a spurious (no-op) PendSV.
pub fn on_tc_irq() -> bool {
    if !ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    let dma = drivers::hpdma::Hpdma1::new();
    dma.clear_flags(CH);

    let k = K.load(Ordering::SeqCst) as u8;
    let hot = HOT.load(Ordering::SeqCst) as u8;
    let pos = POS.load(Ordering::SeqCst) as u8;
    let ph = EVICT_PHASE.load(Ordering::SeqCst);
    let (npos, nph) = logic::advance(pos, ph);
    POS.store(npos as u32, Ordering::SeqCst);
    EVICT_PHASE.store(nph, Ordering::SeqCst);

    // Next transfer first (keep the DMA busy), then let PendSV do the maintenance.
    if let Some(x) = logic::xfer_at(k, hot, npos, nph) {
        kick(x);
    }
    if !ph {
        // A restore just landed (or the chain completed) — PendSV grows/finishes the reveal.
        // SAFETY: SCB ICSR PendSV-set.
        unsafe {
            core::ptr::write_volatile(0xE000_ED04 as *mut u32, 1 << 28);
        }
    }
    true
}

/// PendSV seam. Cache maintenance + progressive reveal; closes the chain on completion.
/// Returns true if the chain consumed this PendSV.
pub fn on_pendsv() -> bool {
    if !ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    let k = K.load(Ordering::SeqCst) as u8;
    let hot = HOT.load(Ordering::SeqCst) as u8;
    let pos = POS.load(Ordering::SeqCst) as u8;

    if logic::is_complete(k, hot, pos) {
        if !ACTIVE.swap(false, Ordering::SeqCst) {
            return true; // a fault/drain closed it between the loads — already revealed
        }
        finish_maintenance_and_reveal();
        CHAIN_HITS.fetch_add(1, Ordering::SeqCst);
        return true;
    }

    let hi = logic::revealed_hi(k, hot, pos);
    let cur = REVEALED_HI.load(Ordering::SeqCst) as u8;
    if hi > cur {
        // Invalidate the newly delivered chunks (cur+1 ..= hi, skipping the hot chunk —
        // pre-restored and since WRITTEN by the enclave), then grow the reveal. When the
        // growth crosses the hot chunk, its dedicated region must drop FIRST: two enabled
        // regions matching one address fault on ARMv8-M. The enclave is preempted while
        // PendSV runs, so the brief unmapped window is unobservable.
        invalidate_chunks(cur + 1, hi, hot);
        icache_flush();
        if hot != logic::NO_HOT && hi >= hot && cur < hot {
            disable_region(HOT_REGION);
        }
        let hi_end = chunk_base(hi) + CB - 1;
        let full_base = FULL_BASE.load(Ordering::SeqCst);
        let full_limit = FULL_LIMIT.load(Ordering::SeqCst);
        let kb = chunk_base(k);
        let reveal_lo = if full_base > kb { full_base } else { kb };
        let reveal_hi = if full_limit < hi_end { full_limit } else { hi_end };
        set_region5(reveal_lo, reveal_hi);
        REVEALED_HI.store(hi as u32, Ordering::SeqCst);
    }
    true
}

/// Cache maintenance for the chunks the enclave has NEVER seen revealed, then the full
/// region-5 reveal (close path for both PendSV completion and drain).
///
/// CORRECTNESS: do NOT invalidate the already-revealed range [k, REVEALED_HI]. Those
/// chunks were invalidated BEFORE their reveal, and the incoming enclave has since
/// EXECUTED and WRITTEN there — dirty lines are its live state. An invalidate (no
/// writeback) would discard them and silently rewind the enclave's memory to the
/// DMA-restored snapshot (HW-observed corruption: benchmarks "terminating" with garbage
/// within ~1 s once the per-fault prints stopped masking the overlap). The never-revealed
/// chunks — the straight remainder above REVEALED_HI and the wrapped segment below k —
/// are exactly the ones the enclave cannot have touched (any access would have faulted
/// into drain), so invalidating only those is both safe and sufficient.
fn finish_maintenance_and_reveal() {
    let k = K.load(Ordering::SeqCst) as u8;
    let hot = HOT.load(Ordering::SeqCst) as u8;
    let hi = REVEALED_HI.load(Ordering::SeqCst) as u8;
    // Straight remainder: chunks hi+1 ..= NUM_CHUNKS-1 (delivered, never revealed) —
    // skipping the hot chunk, which was revealed from the prefix and carries the
    // enclave's live writes (dirty lines; invalidating it would rewind them).
    invalidate_chunks(hi + 1, logic::NUM_CHUNKS - 1, hot);
    // Wrapped segment: chunks 0 .. k-1 (delivered last, revealed only by reveal_full).
    if k > 0 {
        invalidate_chunks(0, k - 1, hot);
    }
    // Out-backing: the CPU never writes backings (DMA-only), whole-range is safe.
    let out_backing = crate::prefetch::overlay::backing_addr(OUT_SLOT.load(Ordering::SeqCst) as usize);
    drivers::hpdma::dcache_invalidate_range(out_backing as usize, WINDOW_BYTES as usize);
    icache_flush();
    reveal_full();
}

/// Force-complete any in-flight chain synchronously. Returns true if a live chain was
/// drained. Callable from ANY context (fault, SysTick, SVC, thread mode): flips ACTIVE
/// first so a racing TC IRQ / PendSV falls through to the no-op prefetch seams, then
/// aborts ch2 (redoing the interrupted transfer is idempotent — same src/dst) and runs
/// the remaining pairs with bounded synchronous waits. NEVER waits on PendSV-posted
/// state (anti-deadlock rule).
///
/// SAFETY: single core; ch2 and the backings are the chain's while ACTIVE.
pub unsafe fn drain() -> bool {
    if !ACTIVE.swap(false, Ordering::SeqCst) {
        return false;
    }
    let dma = drivers::hpdma::Hpdma1::new();
    // Abort in-flight; redo from (POS, PHASE) is idempotent — same src/dst, and nothing
    // reads a half-written backing between abort and redo (the only backing readers are
    // the chain's own restores).
    dma.reset_channel(CH);
    // A TC IRQ latched before the abort would otherwise preempt a thread-mode drain and
    // (via the !ACTIVE fall-through to prefetch::on_dma_complete) clear the very flags the
    // sync copies below poll. reset_channel deasserted the line; drop the stale latch too.
    // The sync copies use configure_mem_to_mem (no TCIE), so no new assertions follow.
    core::ptr::write_volatile(NVIC_ICPR2 as *mut u32, HPDMA_CH2_IRQ_BIT);

    let k = K.load(Ordering::SeqCst) as u8;
    let hot = HOT.load(Ordering::SeqCst) as u8;
    let mut pos = POS.load(Ordering::SeqCst) as u8;
    let mut ph = EVICT_PHASE.load(Ordering::SeqCst);
    while let Some(x) = logic::xfer_at(k, hot, pos, ph) {
        let (src, dst) = xfer_src_dst(x);
        dma_copy_sync(src, dst, CB);
        let n = logic::advance(pos, ph);
        pos = n.0;
        ph = n.1;
    }
    POS.store(pos as u32, Ordering::SeqCst);
    finish_maintenance_and_reveal();
    CHAIN_DRAINS.fetch_add(1, Ordering::SeqCst);
    true
}

/// MemManage seam: the incoming enclave touched a still-hidden chunk (the speculation
/// lost the race). Returns true if recovered — the faulting instruction re-executes.
///
/// SAFETY: fault context, single core.
pub unsafe fn on_fault(fault_addr: u32) -> bool {
    let Some(c) = logic::chunk_of(fault_addr, ESS_BASE) else {
        return false; // outside the window — not ours
    };
    if !ACTIVE.load(Ordering::SeqCst) {
        return false; // window fully revealed — not our hidden-chunk fault
    }
    // Learn: this is a chunk the enclave needs early — pre-restore + reveal it in the next
    // switch's sync prefix (last-fault-wins keeps it self-correcting across switches).
    HOT_FOR_SLOT[IN_SLOT.load(Ordering::SeqCst) as usize & 1].store(c as u32, Ordering::SeqCst);
    CHAIN_FAULTS.fetch_add(1, Ordering::SeqCst);

    // NON-DESTRUCTIVE recovery: a point miss must not abandon the whole speculation. When
    // the faulting chunk sits in the straight run above k and no hot region is in play,
    // advance the chain SYNCHRONOUSLY only up to c (fill + reveal the gap via region 5),
    // then let the background chain keep carrying the chunks beyond c — they can still HIT.
    // Otherwise (wrapped chunk, or a hot region active) fall back to a full sync drain.
    let k = K.load(Ordering::SeqCst) as u8;
    let hot = HOT.load(Ordering::SeqCst) as u8;
    let rev = REVEALED_HI.load(Ordering::SeqCst) as u8;
    if hot == logic::NO_HOT && c > k && c < logic::NUM_CHUNKS && c > rev {
        partial_advance_to(k, c, rev);
    } else {
        drain();
    }
    true
}

/// Non-destructive fault recovery: abort the in-flight transfer, synchronously restore +
/// reveal chunks `rev+1 ..= c` (growing region 5 to c), then resume the background chain
/// for the chunks beyond c. Precondition (checked by the caller): hot == NO_HOT, and
/// k < c < NUM_CHUNKS, rev < c — so the whole gap is the contiguous straight run above k.
///
/// SAFETY: fault context, single core; ch2 and the backings are the chain's.
unsafe fn partial_advance_to(k: u8, c: u8, rev: u8) {
    let dma = drivers::hpdma::Hpdma1::new();
    dma.reset_channel(CH); // abort the in-flight background transfer
    core::ptr::write_volatile(NVIC_ICPR2 as *mut u32, HPDMA_CH2_IRQ_BIT); // drop stale latch

    // Sync-restore the gap rev+1 ..= c (evict A[i] -> backing, restore B[i] -> window).
    // These chunks were hidden, so the enclave cannot have written them — restore is safe.
    let out = OUT_SLOT.load(Ordering::SeqCst);
    let in_ = IN_SLOT.load(Ordering::SeqCst);
    let mut i = rev + 1;
    while i <= c {
        dma_copy_sync(chunk_base(i), backing_chunk(out, i), CB); // evict A[i]
        dma_copy_sync(backing_chunk(in_, i), chunk_base(i), CB); // restore B[i]
        i += 1;
    }
    invalidate_chunks(rev + 1, c, logic::NO_HOT);
    icache_flush();

    // Grow region 5 to cover [k, c], clamped to the enclave extent.
    let hi_end = chunk_base(c) + CB - 1;
    let full_base = FULL_BASE.load(Ordering::SeqCst);
    let full_limit = FULL_LIMIT.load(Ordering::SeqCst);
    let kb = chunk_base(k);
    let reveal_lo = if full_base > kb { full_base } else { kb };
    let reveal_hi = if full_limit < hi_end { full_limit } else { hi_end };
    set_region5(reveal_lo, reveal_hi);
    REVEALED_HI.store(c as u32, Ordering::SeqCst);

    // Resume the chain at the pair AFTER c. With hot == NO_HOT the chain visits chunks in
    // straight order, so c is at position (c - k); the next pair is (c - k + 1), evict phase.
    let npos = (c - k) + 1;
    POS.store(npos as u32, Ordering::SeqCst);
    EVICT_PHASE.store(true, Ordering::SeqCst);
    if let Some(x) = logic::xfer_at(k, logic::NO_HOT, npos, true) {
        kick(x); // background chain carries chunks beyond c — still ACTIVE
    } else {
        // nothing left in the chain (xfer_at exhausted) — close it.
        if ACTIVE.swap(false, Ordering::SeqCst) {
            finish_maintenance_and_reveal();
        }
    }
}

