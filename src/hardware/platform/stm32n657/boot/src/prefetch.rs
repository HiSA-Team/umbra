//! Async speculative prefetch engine (N657). A block is loaded in the BACKGROUND via
//! HPDMA1 channel 2 (TC IRQ 70) while the CPU keeps running; the TC IRQ defers the
//! install to **PendSV** (lowest priority — it runs outside the enclave/SysTick execution
//! window, mirroring the L552 G3 design so the cache-maintenance window never overlaps
//! unprivileged enclave code). Nothing here waits: `start_async` returns immediately and
//! the DMA→IRQ→PendSV chain completes on its own.
//!
//! This is the async MECHANISM. Driving it with real block prediction needs eviction to
//! create the misses (a freshly-created enclave has every block loaded + measured, so
//! there is nothing to prefetch) — see `project_n657_eviction_feasibility`. The boot
//! self-test (`self_test`) proves the chain in isolation: it kicks a background copy and
//! the ISR-posted flag confirms the IRQ + PendSV ran without any inline wait.

use arm::mmio::ICIALLU;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Channel dedicated to prefetch — clear of the crypto DMA channels (0/1).
const PREFETCH_CH: u8 = 2;

/// Posted by the PendSV install once a background transfer completes.
pub static PREFETCH_DONE: AtomicBool = AtomicBool::new(false);
/// Diagnostic: number of async installs (proves the DMA→IRQ→PendSV chain fired).
pub static PREFETCH_HITS: AtomicU32 = AtomicU32::new(0);

// The in-flight transfer's destination + length, read by the PendSV install for the
// cache maintenance. One transfer in flight at a time (single channel).
static IN_FLIGHT_DST: AtomicU32 = AtomicU32::new(0);
static IN_FLIGHT_LEN: AtomicU32 = AtomicU32::new(0);

// NVIC / SCB wiring. HPDMA1 ch2 = IRQ 70 (ch0-15 = 68-83). See reference_n657_irqn_table.
const NVIC_ISER2: u32 = 0xE000_E108; // IRQ 64..95 set-enable
const NVIC_ICPR2: u32 = 0xE000_E288; // IRQ 64..95 clear-pending
const HPDMA_CH2_BIT: u32 = 1 << (70 - 64); // ISER2 bit 6
const NVIC_IPR70: u32 = 0xE000_E400 + 70; // per-IRQ priority byte for IRQ 70
const SCB_ICSR: u32 = 0xE000_ED04;
const ICSR_PENDSVSET: u32 = 1 << 28;
const SHPR3: u32 = 0xE000_ED20; // PendSV priority in bits [23:16]
const PREFETCH_IRQ_PRIO: u8 = 0x80; // below the crypto path (HASH 0x00, SVC/SysTick 0x40)
const PENDSV_PRIO: u32 = 0xE0; // lowest — the install defers to everything

static SETUP_DONE: AtomicBool = AtomicBool::new(false);

/// One-time (idempotent): prefetch IRQ priority below the crypto path, PendSV to the
/// lowest priority (preserving the SysTick byte set by `crypto_wait::hash_irq_setup`),
/// clear stale pending, and enable the NVIC line for IRQ 70.
fn nvic_setup() {
    if SETUP_DONE.swap(true, Ordering::SeqCst) {
        return;
    }
    // SAFETY: NVIC priority/enable + SHPR3 RMW — device registers, idempotent.
    unsafe {
        core::ptr::write_volatile(NVIC_IPR70 as *mut u8, PREFETCH_IRQ_PRIO);
        let s3 = core::ptr::read_volatile(SHPR3 as *const u32);
        core::ptr::write_volatile(SHPR3 as *mut u32, (s3 & 0xFF00_FFFF) | (PENDSV_PRIO << 16));
        core::ptr::write_volatile(NVIC_ICPR2 as *mut u32, HPDMA_CH2_BIT);
        core::ptr::write_volatile(NVIC_ISER2 as *mut u32, HPDMA_CH2_BIT);
    }
}

/// Kick a background DMA load of `len` bytes `src`→`dst` and RETURN immediately. The TC
/// IRQ + PendSV install fire on their own when it completes; poll [`PREFETCH_DONE`] only
/// if you must observe it (the real prefetch never does — the enclave just runs).
///
/// SAFETY: `src`/`dst` must be DMA-reachable, word-aligned, and `len` a multiple of 4.
pub unsafe fn start_async(src: u32, dst: u32, len: u32) {
    nvic_setup();
    PREFETCH_DONE.store(false, Ordering::SeqCst);
    IN_FLIGHT_DST.store(dst, Ordering::SeqCst);
    IN_FLIGHT_LEN.store(len, Ordering::SeqCst);
    drivers::hpdma::enable_clock();
    let dma = drivers::hpdma::Hpdma1::new();
    dma.set_channel_secure(PREFETCH_CH);
    dma.reset_channel(PREFETCH_CH);
    dma.start_mem_to_mem_irq(PREFETCH_CH, src, dst, len);
}

/// HPDMA1 channel-2 TC ISR seam (`handlers.rs::HPDMA1_Channel2_Handler`). Clears the
/// channel flags (deasserts the IRQ line) and defers the install to PendSV.
pub fn on_dma_complete() {
    let dma = drivers::hpdma::Hpdma1::new();
    dma.clear_flags(PREFETCH_CH);
    // SAFETY: set PendSV pending — the deferred install runs at the lowest priority.
    unsafe {
        core::ptr::write_volatile(SCB_ICSR as *mut u32, ICSR_PENDSVSET);
    }
}

/// PendSV install seam (`handlers.rs::umbra_pendsv_handler`). The DMA already wrote the
/// block straight to RAM; INVALIDATE the destination's D-cache lines (a clean would push
/// stale lines over it) + the I-cache so the enclave's fetch reloads from RAM, then post
/// done. In the real prefetch this also marks the block loaded and kicks the next one.
pub fn on_pendsv() {
    let dst = IN_FLIGHT_DST.load(Ordering::SeqCst);
    let len = IN_FLIGHT_LEN.load(Ordering::SeqCst);
    if len == 0 {
        return; // spurious PendSV (nothing in flight)
    }
    drivers::hpdma::dcache_invalidate_range(dst as usize, len as usize);
    // SAFETY: invalidate the I-cache so instruction fetches reload the DMA-written bytes.
    unsafe {
        core::ptr::write_volatile(ICIALLU, 0);
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
    }
    IN_FLIGHT_LEN.store(0, Ordering::SeqCst);
    PREFETCH_HITS.fetch_add(1, Ordering::SeqCst);
    PREFETCH_DONE.store(true, Ordering::SeqCst);
    // Real async ESS-miss: the DMA restored an evicted tail; reveal it (MPU) so the enclave
    // can execute it with no fault. The generic cache maintenance above already ran.
    #[cfg(feature = "async_ess_miss")]
    async_ess::on_prefetch_done();
}

// Word-aligned source + dest for the self-contained boot self-test (256 B = one block).
#[repr(C, align(4))]
struct Buf([u32; 64]);
static mut SELF_TEST_SRC: Buf = Buf([0u32; 64]);
static mut SELF_TEST_DST: Buf = Buf([0u32; 64]);

/// Prove the async chain in isolation: fill a source pattern, kick a BACKGROUND copy
/// source→dest, then observe (via the ISR-posted flag — the DMA + install run in the IRQ
/// and PendSV, not inline) that the chain ran and the bytes match. Returns `(hits, ok)`:
/// hits ≥ 1 and ok true prove the DMA→TC-IRQ→PendSV pipeline fired end-to-end. Self-
/// contained (two statics, no ESS/flash dependency). Never in a production image.
///
/// SAFETY: single-threaded Secure boot context; exclusive use of the two statics here.
pub unsafe fn self_test() -> (u32, bool) {
    let src = core::ptr::addr_of_mut!(SELF_TEST_SRC) as *mut u32;
    let dst = core::ptr::addr_of_mut!(SELF_TEST_DST) as u32;
    let mut i = 0usize;
    while i < 64 {
        core::ptr::write_volatile(src.add(i), 0xA5A5_0000 | i as u32);
        i += 1;
    }
    // Clean the source out of D-cache so the background DMA reads the CPU's writes.
    drivers::hpdma::dcache_clean_range(src as usize, 256);

    let before = PREFETCH_HITS.load(Ordering::SeqCst);
    start_async(src as u32, dst, 256);
    // Bounded OBSERVE — the work (DMA + install) happens in the IRQ + PendSV, not here.
    let mut budget = 4_000_000u32;
    while !PREFETCH_DONE.load(Ordering::SeqCst) && budget > 0 {
        budget -= 1;
    }
    let hits = PREFETCH_HITS.load(Ordering::SeqCst).wrapping_sub(before);
    let s = core::slice::from_raw_parts(src as *const u8, 256);
    let d = core::slice::from_raw_parts(dst as *const u8, 256);
    (hits, s == d)
}

// ── Phase 2a probe: prove the RISAF data-read trap (the M33 lacked it) ───────────
// A standalone 4 KB page (align 4096 → its own RISAF granule). Feature-gated.
#[cfg(feature = "eviction_probe")]
#[repr(C, align(4096))]
struct Page4K([u8; 4096]);
#[cfg(feature = "eviction_probe")]
static mut RISAF_SCRATCH: Page4K = Page4K([0u8; 4096]);

/// Probe the RISAF data-read trap: write a pattern to a 4 KB-aligned scratch, RISAF-protect
/// it (deny CID 1 read via RDENC=0), then READ it — the load must FAULT (this is the trap
/// L552's M33 could not provide). The fault dump reveals WHICH fault fires (BusFault vs
/// SecureFault) + the address, which tells us where the eviction-miss recovery hooks. If
/// the read does NOT fault, the trap did not engage (RISAF region priority) and it prints
/// so. HALTS on the fault — a one-shot diagnostic, never in a production image.
///
/// SAFETY: single-threaded Secure boot; the scratch is a dedicated standalone 4 KB page.
#[cfg(feature = "eviction_probe")]
pub unsafe fn risaf_trap_probe() {
    let scratch = core::ptr::addr_of_mut!(RISAF_SCRATCH) as u32;
    core::ptr::write_volatile(scratch as *mut u32, 0xC0FF_EE00);
    // Push the write to RAM and DROP the cached copy, so the read below MISSES the cache
    // and actually reaches the AXI bus where the RISAF checks it (a cache hit never would).
    drivers::hpdma::dcache_clean_range(scratch as usize, 32);
    drivers::hpdma::dcache_invalidate_range(scratch as usize, 32);

    crate::raw_print::print_str("[EVICT] protect scratch @0x");
    crate::raw_print::print_hex(scratch);
    crate::raw_print::print_str(" via RISAF3 region 7 (deny CID1 read)\n");
    let risaf = drivers::risaf::Risaf::new(drivers::risaf::RisafInstance::Risaf3);
    // read_cid_mask = 0, write_cid_mask = 0 → no compartment (incl. CID 1) may access.
    risaf.configure_region(7, scratch, scratch + 0x0FFF, true, 0, 0, 0);

    crate::raw_print::print_str("[EVICT] reading protected region (expect a fault)...\n");
    let v = core::ptr::read_volatile(scratch as *const u32);

    // Only reached if the RISAF did NOT trap the read.
    risaf.disable_region(7);
    crate::raw_print::print_str("[EVICT] NO FAULT read=0x");
    crate::raw_print::print_hex(v);
    crate::raw_print::print_str(" iasr=0x");
    crate::raw_print::print_hex(risaf.read_iasr());
    crate::raw_print::print_str(" — RISAF read-trap did NOT fire (region priority?)\n");
}

// ── Phase 2b: MPU hide+restore eviction probe ────────────────────────────────────
// The RISAF RAZ's data reads (no sync fault); the MPU does NOT. The enclave runs
// UNPRIVILEGED with PRIVDEFENA=1, so any address NOT covered by an explicit MPU region
// faults MemManage SYNCHRONOUSLY for it — on DATA loads AND instruction fetches alike
// (unlike the RISAF/UDF, which trap instructions only). This probe hides the enclave's
// entry block by shrinking code region 5, so the first fetch faults; the MemManage handler
// restores region 5 (the content is still in EFBC) and recovers. Proves the trap+restore
// mechanism; freeing EFBC space is the separate cache/context-switch design.
#[cfg(feature = "mpu_evict_probe")]
pub mod mpu_evict {
    use arm::mmio::{MPU_RBAR, MPU_RLAR, MPU_RNR};
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    const CODE_REGION: u32 = 5; // enclave code region (see api_impl enclave_enter)
    const RBAR_RO_EXEC: u32 = 0b11 << 1; // AP=RO any-privilege, XN=0 (executable)

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    /// Evict the entry block ONCE (the first enclave_enter). enclave_enter also runs on
    /// every SysTick resume — without this guard each resume re-hides block 0 and the
    /// enclave never advances past the entry (infinite fault→restore→preempt loop).
    static EVICTED_ONCE: AtomicBool = AtomicBool::new(false);
    static ORIG_BASE: AtomicU32 = AtomicU32::new(0);
    static ORIG_LIMIT: AtomicU32 = AtomicU32::new(0);
    static HIDDEN_LO: AtomicU32 = AtomicU32::new(0);
    static HIDDEN_HI: AtomicU32 = AtomicU32::new(0);
    /// Diagnostic: number of MemManage restores (proves the trap+restore fired).
    pub static RESTORES: AtomicU32 = AtomicU32::new(0);

    fn set_region5(base: u32, limit: u32) {
        // SAFETY: MPU region 5 reprogram — device registers, single-threaded Secure.
        unsafe {
            core::ptr::write_volatile(MPU_RNR, CODE_REGION);
            core::ptr::write_volatile(MPU_RBAR, (base & 0xFFFF_FFE0) | RBAR_RO_EXEC);
            core::ptr::write_volatile(MPU_RLAR, (limit & 0xFFFF_FFE0) | 0x01);
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
        }
    }

    /// Evict the FRONT `bytes` of the code region by moving region 5's base up, so the
    /// hidden entry range is unmapped → the enclave's first fetch faults MemManage.
    /// Call after region 5 is configured in enclave_enter. `bytes` = one block (256).
    pub fn evict_front(code_base: u32, code_limit: u32, bytes: u32) {
        if EVICTED_ONCE.swap(true, Ordering::SeqCst) {
            return; // already evicted once — don't re-hide on SysTick resumes
        }
        let new_base = (code_base + bytes) & 0xFFFF_FFE0;
        ORIG_BASE.store(code_base, Ordering::SeqCst);
        ORIG_LIMIT.store(code_limit, Ordering::SeqCst);
        HIDDEN_LO.store(code_base, Ordering::SeqCst);
        HIDDEN_HI.store(new_base, Ordering::SeqCst);
        ACTIVE.store(true, Ordering::SeqCst);
        set_region5(new_base, code_limit);
    }

    /// MemManage-handler seam. If `fault_addr` is in the hidden range, restore region 5 to
    /// the full [base, limit] (reveal — the content never left EFBC) and return true
    /// (recover: the faulting instruction re-executes and now succeeds).
    pub fn restore(fault_addr: u32) -> bool {
        if !ACTIVE.load(Ordering::SeqCst) {
            return false;
        }
        let lo = HIDDEN_LO.load(Ordering::SeqCst);
        let hi = HIDDEN_HI.load(Ordering::SeqCst);
        if fault_addr < lo || fault_addr >= hi {
            return false; // not our fault — let the normal handler run
        }
        set_region5(ORIG_BASE.load(Ordering::SeqCst), ORIG_LIMIT.load(Ordering::SeqCst));
        ACTIVE.store(false, Ordering::SeqCst);
        RESTORES.fetch_add(1, Ordering::SeqCst);
        true
    }
}

// ── Inter-enclave eviction: EFBC ↔ ESS backing (the feasible eviction on N657) ────
// A set-associative intra-enclave cache is infeasible (no MMU + PC-relative branches — see
// project_n657_eviction_feasibility). The feasible eviction time-multiplexes the EFBC across
// DIFFERENT enclaves: evict enclave A's whole EFBC → an ESS SRAM backing (async DMA), run B in
// the freed EFBC, restore A on re-entry. Each enclave keeps its fixed contiguous layout, so no
// branch relocation is needed. This module is Step 1: prove the evict→ESS→restore round-trip
// preserves the enclave on live state (Step 2 is the real 2-enclave scheduling).
#[cfg(feature = "interenclave_evict")]
pub mod inter_evict {
    use arm::mmio::{ICIALLU, MPU_RBAR, MPU_RNR};
    use core::sync::atomic::{AtomicBool, Ordering};

    const CH: u8 = 2;
    const BACKING_BYTES: usize = 8192; // covers the demo enclave; size to the EFBC for real use

    // ESS backing store (SRAM) holding an evicted enclave's EFBC. Word-aligned for the DMA.
    #[repr(C, align(4))]
    struct Backing([u8; BACKING_BYTES]);
    static mut ESS_BACKING: Backing = Backing([0u8; BACKING_BYTES]);

    static DONE_ONCE: AtomicBool = AtomicBool::new(false);

    fn dma_copy(src: u32, dst: u32, len: u32) {
        let dma = drivers::hpdma::Hpdma1::new();
        dma.reset_channel(CH);
        dma.configure_mem_to_mem(CH, src, dst, len);
        dma.enable_channel(CH);
        let _ = dma.wait_complete(CH, 8_000_000);
        dma.clear_flags(CH);
    }

    /// Evict→ESS→scramble→restore round-trip on enclave A's EFBC `[efbc, efbc+len)`. Proves
    /// the inter-enclave evict+restore preserves the enclave: the scramble (0xDEADBEEF over the
    /// EFBC) is undone only if the restore actually brings A's blocks back from ESS. Runs once
    /// (enclave_enter also runs on every SysTick resume). `len` is bounded by the backing size.
    ///
    /// SAFETY: single-threaded Secure boot; `efbc` is enclave A's mapped EFBC region.
    pub unsafe fn round_trip(efbc: u32, len: u32) -> bool {
        if DONE_ONCE.swap(true, Ordering::SeqCst) {
            return false; // already ran once — enclave_enter also runs on SysTick resumes
        }
        let len = (len as usize).min(BACKING_BYTES) as u32 & 0xFFFF_FFF0;
        if len == 0 {
            return false;
        }
        let backing = core::ptr::addr_of_mut!(ESS_BACKING) as u32;
        drivers::hpdma::enable_clock();
        drivers::hpdma::Hpdma1::new().set_channel_secure(CH);

        // 1. Evict: push A's EFBC to RAM, DMA EFBC → ESS backing.
        drivers::hpdma::dcache_clean_range(efbc as usize, len as usize);
        dma_copy(efbc, backing, len);
        drivers::hpdma::dcache_invalidate_range(backing as usize, len as usize);

        // 2. Scramble the EFBC (simulate enclave B reusing the freed slots). The enclave
        //    code MPU region 5 is RO even to the privileged kernel, so flip it to priv-RW
        //    for the CPU writes, then back. (The DMA copies bypass the MPU — it governs CPU
        //    accesses only — so only this CPU scramble needs the flip.)
        core::ptr::write_volatile(MPU_RNR, 5);
        let saved_rbar = core::ptr::read_volatile(MPU_RBAR);
        core::ptr::write_volatile(MPU_RBAR, saved_rbar & !0x06); // AP=00 (priv RW)
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
        let mut i = 0u32;
        while i < len {
            core::ptr::write_volatile((efbc + i) as *mut u32, 0xDEAD_BEEF);
            i += 4;
        }
        drivers::hpdma::dcache_clean_range(efbc as usize, len as usize);
        core::ptr::write_volatile(MPU_RBAR, saved_rbar); // restore AP=11 (RO)
        core::arch::asm!("dsb");
        core::arch::asm!("isb");

        // 3. Restore: DMA ESS backing → EFBC.
        dma_copy(backing, efbc, len);

        // 4. Invalidate D-cache (drop the scrambled lines WITHOUT writeback) + I-cache so the
        //    enclave fetches A's restored code, not the 0xDEADBEEF.
        drivers::hpdma::dcache_invalidate_range(efbc as usize, len as usize);
        core::ptr::write_volatile(ICIALLU, 0);
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
        true
    }
}

// ── Async ESS-miss: the async engine driving a REAL block recovery while the enclave runs ──
// On N657 enclave_create loads AND measures every block (all `is_loaded`), so the production
// enclave never misses at runtime — the sync ESS-miss dispatcher is dead here, and the only
// thing that would force runtime paging (an enclave bigger than the EFBC) needs the intra-
// enclave cache that is infeasible without an MMU (ADR 011). So an async ESS-miss can only be
// a feature-gated DEMONSTRATOR. It proves the piece that the boot self-test cannot: the async
// DMA→IRQ→PendSV engine recovering an evicted block WHILE the enclave is executing (real
// overlap), with a synchronous fault as the safety net.
//
// Mechanism (data-safe, deadlock-free), composing the proven pieces:
//   arm() at enclave_enter — evict the enclave's back half to an SRAM backing (DMA), then
//     MPU-HIDE the tail by shrinking code region 5 (the MPU gives a synchronous trap on DATA
//     loads AND instruction fetches — unlike UDF-fill, which traps instructions only — so
//     evicting data blocks is safe here), and kick a BACKGROUND async restore backing→tail.
//   The enclave runs its front half; meanwhile the async DMA restores the tail. Two outcomes:
//     • async wins → PendSV reveals the tail (region 5 grows back) before the enclave reaches
//       it → NO fault (a HIT).
//     • enclave outruns the prefetch → it faults MemManage in the hidden tail → the fallback
//       restores synchronously from the backing and reveals → recover (a FAULT).
//   Both converge on a correct, revealed tail; `reveal()` is idempotent so whichever fires
//   first wins and the other is a no-op.
//
// DEADLOCK NOTE: the MemManage fallback must NOT wait on PREFETCH_DONE — that flag is posted by
// PendSV (priority 0xE0, the lowest), which cannot run while we are inside the MemManage fault,
// so it would never be set → hang. The fallback instead ABORTS the async transfer (channel
// reset) and does its own bounded synchronous DMA — the DMA is a bus master that completes
// regardless of CPU exception priority — making the sync copy the authoritative one.
#[cfg(feature = "async_ess_miss")]
pub mod async_ess {
    use arm::mmio::{ICIALLU, MPU_RBAR, MPU_RLAR, MPU_RNR};
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    const CH: u8 = 2; // same background channel as the async engine
    const RBAR_RO_EXEC: u32 = 0b11 << 1; // AP=RO any-privilege, XN=0 (executable)
    const BACKING_BYTES: usize = 8192;

    // Plaintext backing for the evicted tail (SRAM, word-aligned for the DMA).
    #[repr(C, align(4))]
    struct Backing([u8; BACKING_BYTES]);
    static mut TAIL_BACKING: Backing = Backing([0u8; BACKING_BYTES]);

    static ARMED: AtomicBool = AtomicBool::new(false);
    static DONE_ONCE: AtomicBool = AtomicBool::new(false); // enclave_enter re-runs on resume
    static REVEALED: AtomicBool = AtomicBool::new(false);
    static FULL_BASE: AtomicU32 = AtomicU32::new(0);
    static FULL_LIMIT: AtomicU32 = AtomicU32::new(0);
    static TAIL_LO: AtomicU32 = AtomicU32::new(0); // first hidden byte
    static TAIL_LEN: AtomicU32 = AtomicU32::new(0);
    /// Diagnostics: async installs that beat the enclave vs synchronous fault fallbacks.
    pub static HITS: AtomicU32 = AtomicU32::new(0);
    pub static FAULTS: AtomicU32 = AtomicU32::new(0);

    fn set_region5(base: u32, limit: u32) {
        // SAFETY: MPU region 5 reprogram — device registers, single-threaded Secure.
        unsafe {
            core::ptr::write_volatile(MPU_RNR, 5);
            core::ptr::write_volatile(MPU_RBAR, (base & 0xFFFF_FFE0) | RBAR_RO_EXEC);
            core::ptr::write_volatile(MPU_RLAR, (limit & 0xFFFF_FFE0) | 0x01);
            core::arch::asm!("dsb");
            core::arch::asm!("isb");
        }
    }

    /// Reveal the hidden tail (region 5 → full extent). Idempotent: whichever of the async
    /// install or the fault fallback fires first reveals; the other is a no-op.
    fn reveal() {
        if REVEALED.swap(true, Ordering::SeqCst) {
            return;
        }
        set_region5(FULL_BASE.load(Ordering::SeqCst), FULL_LIMIT.load(Ordering::SeqCst));
    }

    /// Arm the demonstrator at enclave_enter (after region 5 is configured). Evicts the back
    /// half of the enclave to the backing, hides it (region 5 shrink), and kicks the async
    /// restore. Runs ONCE (enclave_enter also runs on every SysTick resume). `code_size` is the
    /// enclave's total code bytes (num_blocks × 256).
    ///
    /// SAFETY: single-threaded Secure boot; `[code_base, code_limit]` is the mapped enclave code.
    pub unsafe fn arm(code_base: u32, code_limit: u32, code_size: u32) {
        if DONE_ONCE.swap(true, Ordering::SeqCst) {
            return;
        }
        let num_blocks = code_size / 256;
        if num_blocks < 2 {
            return; // nothing meaningful to split
        }
        // Evict the back half, capped by the backing size (whole blocks).
        let mut tail_blocks = num_blocks / 2;
        if (tail_blocks as usize) * 256 > BACKING_BYTES {
            tail_blocks = (BACKING_BYTES / 256) as u32;
        }
        let tail_len = tail_blocks * 256;
        let tail_lo = (code_limit + 1) - tail_len; // 256-aligned (code is block-aligned)
        let backing = core::ptr::addr_of_mut!(TAIL_BACKING) as u32;

        drivers::hpdma::enable_clock();
        let dma = drivers::hpdma::Hpdma1::new();
        dma.set_channel_secure(CH);

        // ponytail: the tail is FENCED (MPU-hidden) + restored, NOT cleared. Genuinely wiping
        // it would be unsafe here — enclave_enter re-reveals region 5 to its full extent on
        // every SysTick resume, so a resume landing before the restore would expose a wiped
        // tail. Keeping the content intact makes the demonstrator corruption-proof; the async
        // DMA still exercises a real ESS write under the running enclave and the MPU trap+reveal
        // is the load-bearing part. Load-from-flash+decrypt (a genuinely absent block) is the
        // heavier upgrade — it needs the region-5 reveal coordinated with this module.

        // 1. Save the tail → backing (the DMA bypasses the MPU, so region 5 need not be
        //    flipped). Clean it out of D-cache first so the DMA reads the committed bytes.
        drivers::hpdma::dcache_clean_range(tail_lo as usize, tail_len as usize);
        dma.reset_channel(CH);
        dma.configure_mem_to_mem(CH, tail_lo, backing, tail_len);
        dma.enable_channel(CH);
        let _ = dma.wait_complete(CH, 8_000_000);
        dma.clear_flags(CH);
        drivers::hpdma::dcache_invalidate_range(backing as usize, tail_len as usize);

        // 2. Hide the tail: shrink region 5 to [base, tail_lo). Now any access to the tail —
        //    data OR instruction — faults MemManage synchronously.
        FULL_BASE.store(code_base, Ordering::SeqCst);
        FULL_LIMIT.store(code_limit, Ordering::SeqCst);
        TAIL_LO.store(tail_lo, Ordering::SeqCst);
        TAIL_LEN.store(tail_len, Ordering::SeqCst);
        REVEALED.store(false, Ordering::SeqCst);
        ARMED.store(true, Ordering::SeqCst);
        set_region5(code_base, tail_lo - 1);

        // 3. Kick the BACKGROUND async restore backing→tail. The DMA→TC-IRQ→PendSV chain
        //    reveals the tail on its own (super::on_pendsv → on_prefetch_done). The enclave
        //    starts running its front half immediately; nothing here waits.
        super::start_async(backing, tail_lo, tail_len);

        // Confirm the demonstrator armed. A HIT (async reveal before the enclave reaches the
        // tail) is silent; a [ASYNC-ESS] sync restore print means the enclave outran it.
        crate::raw_print::print_str("[ASYNC-ESS] evicted tail ");
        crate::raw_print::print_hex(tail_blocks);
        crate::raw_print::print_str(" blocks @0x");
        crate::raw_print::print_hex(tail_lo);
        crate::raw_print::print_str(", async restore kicked\n");
    }

    /// on_pendsv seam (called from `super::on_pendsv` after its cache maintenance). The async
    /// DMA restored the tail and the engine already invalidated its D-/I-cache lines; reveal
    /// the tail so the enclave can execute it with no fault.
    pub fn on_prefetch_done() {
        if !ARMED.load(Ordering::SeqCst) {
            return;
        }
        if REVEALED.load(Ordering::SeqCst) {
            return; // the fault fallback already revealed
        }
        reveal();
        HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// MemManage-handler seam. If `fault_addr` is in the hidden tail, the enclave outran the
    /// prefetch: ABORT the async transfer, restore the tail SYNCHRONOUSLY from the backing (the
    /// DMA completes regardless of CPU priority — no PendSV dependency, so no deadlock), reveal,
    /// and return true (recover). Returns false if not our fault.
    ///
    /// SAFETY: fault context, single-threaded Secure; `CH` and the backing are ours exclusively.
    pub unsafe fn on_fault(fault_addr: u32) -> bool {
        if !ARMED.load(Ordering::SeqCst) || REVEALED.load(Ordering::SeqCst) {
            return false;
        }
        let lo = TAIL_LO.load(Ordering::SeqCst);
        let len = TAIL_LEN.load(Ordering::SeqCst);
        if fault_addr < lo || fault_addr >= lo + len {
            return false; // not the hidden tail — let the normal handler run
        }
        let backing = core::ptr::addr_of_mut!(TAIL_BACKING) as u32;
        let dma = drivers::hpdma::Hpdma1::new();
        dma.reset_channel(CH); // abort any in-flight async transfer — the sync copy wins
        dma.configure_mem_to_mem(CH, backing, lo, len);
        dma.enable_channel(CH);
        let _ = dma.wait_complete(CH, 8_000_000);
        dma.clear_flags(CH);
        drivers::hpdma::dcache_invalidate_range(lo as usize, len as usize);
        core::ptr::write_volatile(ICIALLU, 0);
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
        reveal();
        FAULTS.fetch_add(1, Ordering::SeqCst);
        true
    }
}

// ── Inter-enclave OVERLAY: time-multiplex the EFBC across TWO live enclaves ────────
// The feasible eviction (project_n657_eviction_feasibility): two enclaves both linked to
// the EFBC base can't coexist (their images overlap / exceed 64 blocks), so only ONE is
// resident at a time; the other lives in an SRAM backing. The SysTick preemption switch
// uses `overlay_chain::begin_switch` (speculative per-chunk chain: sync resume-PC prefix +
// background DMA + progressive MPU reveal). `make_resident(slot)` serves only the COLD
// host-driven paths — enclave_create (2nd create evicts the 1st) and enclave_enter
// (entering a non-resident enclave) — as a fully synchronous, drain-guarded whole-window
// evict→restore (generalizing the HW-verified inter_evict::round_trip). Backings are
// sized to the full 16 KB window and shared with the chain via `backing_addr`.
#[cfg(feature = "interenclave_overlay")]
pub mod overlay {
    use arm::mmio::{ICIALLU, MPU_RBAR, MPU_RNR};
    use core::sync::atomic::{AtomicI32, Ordering};

    const CH: u8 = 2; // background DMA channel (shared with the async engine; used synchronously here)
    const WINDOW_BYTES: usize = 0x4000; // full 16 KB EFBC window = umbra-ess-core ESS_SIZE
    pub const NUM_SLOTS: usize = 2; // MAX_ENCLAVES_CTX

    #[repr(C, align(4))]
    struct Backing([u8; WINDOW_BYTES]);
    static mut BACKINGS: [Backing; NUM_SLOTS] =
        [Backing([0u8; WINDOW_BYTES]), Backing([0u8; WINDOW_BYTES])];

    /// Which enclave slot's image is currently in the EFBC window (-1 = none/fresh).
    pub static RESIDENT: AtomicI32 = AtomicI32::new(-1);
    /// Diagnostic: number of overlay switches (evict+restore) performed.
    pub static SWITCHES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    fn dma_copy(src: u32, dst: u32, len: u32) {
        let dma = drivers::hpdma::Hpdma1::new();
        dma.reset_channel(CH);
        dma.configure_mem_to_mem(CH, src, dst, len);
        dma.enable_channel(CH);
        let _ = dma.wait_complete(CH, 8_000_000);
        dma.clear_flags(CH);
    }

    /// Evict the whole EFBC window `[efbc, efbc+WINDOW_BYTES)` → BACKINGS[slot].
    /// SAFETY: single-threaded Secure; `slot < NUM_SLOTS`; the DMA bypasses the MPU.
    unsafe fn evict(slot: usize, efbc: u32) {
        let backing = core::ptr::addr_of_mut!(BACKINGS[slot]) as u32;
        drivers::hpdma::enable_clock();
        drivers::hpdma::Hpdma1::new().set_channel_secure(CH);
        drivers::hpdma::dcache_clean_range(efbc as usize, WINDOW_BYTES);
        dma_copy(efbc, backing, WINDOW_BYTES as u32);
        drivers::hpdma::dcache_invalidate_range(backing as usize, WINDOW_BYTES);
    }

    /// Restore BACKINGS[slot] → the EFBC window, cache-coherent for execution.
    /// SAFETY: single-threaded Secure; `slot < NUM_SLOTS`.
    unsafe fn restore(slot: usize, efbc: u32) {
        let backing = core::ptr::addr_of_mut!(BACKINGS[slot]) as u32;
        drivers::hpdma::enable_clock();
        drivers::hpdma::Hpdma1::new().set_channel_secure(CH);
        // Flip region 5 to priv-RW (AP=00) around the code overwrite, mirroring the ESS-miss
        // path (region 5 is normally AP=01 RW-any; the DMA bypasses the MPU regardless).
        core::ptr::write_volatile(MPU_RNR, 5);
        let saved = core::ptr::read_volatile(MPU_RBAR);
        core::ptr::write_volatile(MPU_RBAR, saved & !0x06);
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
        dma_copy(backing, efbc, WINDOW_BYTES as u32);
        core::ptr::write_volatile(MPU_RBAR, saved);
        drivers::hpdma::dcache_invalidate_range(efbc as usize, WINDOW_BYTES);
        core::ptr::write_volatile(ICIALLU, 0);
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
    }

    /// Make enclave `slot`'s image resident in the EFBC window `efbc` (= ESS_BASE). If another
    /// slot is resident, evict it → its backing first. Then, unless `fresh_load` (the caller is
    /// about to load the image itself, e.g. at create), restore `slot` ← its backing. Tracks
    /// RESIDENT. Returns true if a switch (evict and/or restore) happened.
    ///
    /// Cold host-driven paths ONLY (enclave_create / enclave_enter): fully synchronous,
    /// drain-guarded. The SysTick preemption switch does NOT come through here — it uses
    /// `overlay_chain::begin_switch` (speculative chunk chain).
    ///
    /// SAFETY: single-threaded Secure; `slot < NUM_SLOTS`; `efbc` is the ESS window base.
    pub unsafe fn make_resident(slot: usize, efbc: u32, fresh_load: bool) -> bool {
        crate::overlay_chain::drain(); // never overlap a live chain with a sync window copy
        let cur = RESIDENT.load(Ordering::SeqCst);
        if cur == slot as i32 {
            return false; // already resident — no switch
        }
        if cur >= 0 {
            evict(cur as usize, efbc);
        }
        if !fresh_load {
            restore(slot, efbc);
        }
        RESIDENT.store(slot as i32, Ordering::SeqCst);
        if cur >= 0 {
            SWITCHES.fetch_add(1, Ordering::SeqCst);
        }
        true
    }

    /// Evict whatever enclave is currently resident (if any) → its backing and mark the window
    /// empty. `enclave_create` calls this before it loads a NEW enclave fresh into the window,
    /// so the outgoing enclave's image survives in its backing for a later restore-on-enter.
    /// SAFETY: single-threaded Secure; `efbc` = ESS window base.
    pub unsafe fn evict_current(efbc: u32) {
        crate::overlay_chain::drain(); // never overlap a live chain with a sync window copy
        let cur = RESIDENT.load(Ordering::SeqCst);
        if cur >= 0 {
            evict(cur as usize, efbc);
            RESIDENT.store(-1, Ordering::SeqCst);
        }
    }

    /// Mark slot `slot` as resident — its image is now in the window (e.g. just loaded fresh by
    /// `enclave_create`). No DMA; pairs with `evict_current`.
    pub fn set_resident(slot: usize) {
        RESIDENT.store(slot as i32, Ordering::SeqCst);
    }

    /// Base address of slot `slot`'s backing store (for the async chain's per-chunk DMA).
    /// SAFETY-relevant: callers stay within `[addr, addr + WINDOW_BYTES)`.
    pub fn backing_addr(slot: usize) -> u32 {
        unsafe { core::ptr::addr_of_mut!(BACKINGS[slot]) as u32 }
    }
}
