//! Monitor-side enclave kernel — the M-mode TCB glue between the `ecall` API and
//! the platform-agnostic `kernel` crate (the same crate the STM32 platforms
//! use). Enclave identity is parsed with `kernel::common::enclave`
//! (`UmbraEnclaveHeader` / `EnclaveDescriptor`), exactly as L552 does.
//!
//! Execution is RISC-V-specific: the enclave is a plain function at the code
//! start (`base + UMBRA_HEADER_SIZE`); the monitor enters it in U-mode with `ra`
//! set to a return sentinel, and when it returns the fetch at the sentinel
//! faults back to M — **Umbra handles the exit** (the EFB model: the monitor
//! catches the enclave's return rather than the enclave signalling completion).

use kernel::common::enclave::{EnclaveDescriptor, UmbraEnclaveHeader, UMBRA_HEADER_SIZE};
use kernel::common::ess::{CACHE_LIMIT_PER_ENCLAVE, ESS_BASE};
use kernel::key_storage_server::crypto::CryptoEngine;
use umbra_error::{UmbraError, UmbraResult};
use umbra_riscv_arch::csr::PmpCfg;
use umbra_riscv_arch::pmp::{self, Region};
use umbra_riscv_arch::spmp::{self, cfg_bits};
use umbra_riscv_arch::trap::TrapFrame;

use crate::crypto_impl;
use crate::platform_impl::timer;
use crate::raw_print;

// ── Fixed memory map (shared with the host linker + the SPMP setup) ──────────
/// U-mode host image entry (`_host_start`).
pub const HOST_ENTRY: u32 = 0x8010_0000;
/// Host working region `[base, base+size)` — code/rodata/data/bss/stack.
pub const HOST_REGION_BASE: u32 = 0x8010_0000;
pub const HOST_REGION_SIZE: u32 = 0x0004_0000; // 256 KB
/// Initial host stack pointer (the host's `_host_start` resets it anyway).
pub const HOST_SP: u32 = HOST_REGION_BASE + HOST_REGION_SIZE;
/// Top of the host-world PMP grant: the host (S) owns `[HOST_REGION_BASE, ESS_BASE)`,
/// which spans its code/data/stack and the embedded enclave ciphertext it scans.
pub const HOST_WORLD_END: u32 = ESS_BASE;
/// Enclave code (ESS) region `[ESS_BASE, ESS_CODE_END)` — enclave-world PMP R-X.
/// The decrypted/demand-loaded blocks live and execute here in U-mode.
pub const ESS_CODE_END: u32 = ESS_BASE + 0x0001_0000; // 64 KB
/// Enclave stack region `[ENC_STACK_BASE, ENC_STACK_TOP)` — enclave-world PMP R-W.
pub const ENC_STACK_BASE: u32 = 0x8021_0000;
pub const ENC_STACK_TOP: u32 = 0x8022_0000;
/// Initial enclave stack pointer (grows down from the top of the R-W region).
pub const ENC_SP: u32 = ENC_STACK_TOP;
/// `ra` the monitor installs before entering the enclave. The enclave's final
/// `ret` jumps here; the fetch faults to M and is recognized as a clean return.
pub const RETURN_SENTINEL: u32 = 0x0000_0000;

/// Status word the host reads from the packed `enter` return (`(status<<8)|...`).
pub const STATUS_TERMINATED: u32 = 4;
/// The enclave was preempted by the timer mid-execution; the host (scheduler)
/// re-enters it to resume. Matches the host's `STATUS_SUSPENDED`.
pub const STATUS_SUSPENDED: u32 = 3;

/// Enclave ids stay below the host-reserved error band (the host treats an id
/// `>= 0xFFFF_FFF0` as an error — the same ABI invariant as the ARM platforms).
pub const MAX_ENCLAVE_ID: u32 = 0xFFFF_FFEF;

pub fn id_is_valid(id: u32) -> bool {
    id <= MAX_ENCLAVE_ID
}

// ── EFB block format (chained + ess_miss_recovery) ──────────────────────────
// Mirrors `tools/protect_enclave.py` + L552 `secure_kernel/init.rs`. Each
// on-image block is `[sig(32) | meta(32) | ciphertext(256)]` = 320 bytes:
//   sig  = per-block HMAC (used by the runtime ESS-miss re-validation, 2b)
//   meta = [reachable_count(1) | reachable_idx(1)*N | pad] to 32 bytes
//   ct   = AES-128-CTR(enc_key, IV=0) of the 256-byte plaintext block
// The blob (N blocks + reloc table) starts at `base + UMBRA_HEADER_SIZE`.
/// Executable code bytes per block (the ESS slot size). Matches the host
/// `protect_enclave.py` `UMBRA_SLOT_SIZE_BYTES` default.
pub const CODE_BLOCK_SIZE: u32 = 256;
const BLOCK_META_OFFSET: u32 = 32;
const BLOCK_CT_OFFSET: u32 = 64;
/// On-image bytes per block (`sig + meta + ciphertext`).
pub const TOTAL_BLOCK_SIZE: u32 = CODE_BLOCK_SIZE + 64;
/// Max reachable entries per block stored in `meta` (kernel `MAX_REACHABLE`).
const MAX_REACHABLE: usize = 4;
/// Upper bound on blocks per enclave (BFS queue / loaded-bitmap width).
const MAX_EFBS: usize = 32;
// Max blocks resident in ESS at once per enclave = the production build-time
// knob `UMBRA_CACHE_LIMIT` (default 64), shared with L552 via the kernel crate
// (`kernel::common::ess::CACHE_LIMIT_PER_ENCLAVE`, imported above). At 64 ≫
// MAX_EFBS the cache holds every block of a normal enclave, so eviction only
// fires for enclaves larger than the cache; block 0 (entry) is never evicted.
// Build with `UMBRA_CACHE_LIMIT=2` to exercise the eviction path on the demo.
/// Illegal-instruction fill for unloaded ESS slots: `0x0000` is an illegal
/// compressed instruction at any halfword offset, so an instruction fetch into
/// an unloaded block always traps to M (mcause = 2 illegal instruction).
const TRAP_FILL: u8 = 0x00;

/// Fill a block-sized ESS slot with the trap pattern so a fetch into it faults.
/// SAFETY: `ess_slot` is a CODE_BLOCK_SIZE region inside the enclave's ESS.
unsafe fn trap_fill_slot(ess_slot: u32) {
    core::ptr::write_bytes(ess_slot as *mut u8, TRAP_FILL, CODE_BLOCK_SIZE as usize);
}

/// Decrypt-install one block's ciphertext (`ct_ptr`, in the host image) into its
/// ESS slot, AES-128-CTR-decrypting through the `CryptoEngine` (same boundary the
/// STM32 platforms use). SAFETY: `ct_ptr` points at a CODE_BLOCK_SIZE
/// ciphertext; `ess_slot` is the matching ESS region.
unsafe fn install_block(
    crypto: &mut dyn CryptoEngine,
    enc_key: &[u8],
    ct_ptr: *const u8,
    ess_slot: u32,
) {
    core::ptr::copy_nonoverlapping(ct_ptr, ess_slot as *mut u8, CODE_BLOCK_SIZE as usize);
    let slot = core::slice::from_raw_parts_mut(ess_slot as *mut u8, CODE_BLOCK_SIZE as usize);
    // CTR is symmetric (decrypt == keystream XOR); IV = 0 matches the signer.
    let _ = crypto.aes_decrypt(enc_key, &[0u8; 16], slot);
}

/// `fence.i` — make freshly-installed code visible to instruction fetch (forces
/// QEMU to re-translate the modified block; I-cache/pipeline sync on real HW).
fn fence_i() {
    #[cfg(target_arch = "riscv32")]
    // SAFETY: `fence.i` has no operands; it only orders self-modified code.
    unsafe {
        core::arch::asm!("fence.i")
    };
}

// Slots indexed by enclave id. Ids start at 1 (the host reserves 0 as an
// "empty slot" sentinel — `if enclave_ids[i] == 0 continue`), matching the L552
// `NEXT_ENCLAVE_ID = 1` convention.
const MAX_ENCLAVES: usize = 8;

#[derive(Clone, Copy)]
struct Slot {
    descriptor: EnclaveDescriptor,
    result: u32,
    used: bool,
    /// Set while the enclave is preempted: `saved_ctx` holds its full register
    /// context and the next `enter` resumes from it instead of restarting.
    suspended: bool,
    /// The enclave's register file + `mepc`/`mstatus` snapshot taken at the
    /// preemption tick (the RISC-V analog of L552's saved PSP context).
    saved_ctx: TrapFrame,
    /// Number of 320-byte EFB blocks this enclave was divided into.
    num_blocks: u32,
    /// Per-block residency: `true` once the block's plaintext sits in its ESS
    /// slot. Block 0 (entry) is loaded at `create` and never evicted; the rest
    /// fault in on demand and may be evicted under the cache limit.
    block_loaded: [bool; MAX_EFBS],
    /// Per-block use counter (LFU-ish): bumped on each (re)load so eviction can
    /// pick the least-used victim.
    block_counter: [u32; MAX_EFBS],
}

const EMPTY_SLOT: Slot = Slot {
    descriptor: EnclaveDescriptor {
        id: 0,
        flash_base: 0,
        ram_base: 0,
        code_size: 0,
        entry_point: 0,
        is_loaded: false,
    },
    result: 0,
    used: false,
    suspended: false,
    saved_ctx: ZERO_FRAME,
    num_blocks: 0,
    block_loaded: [false; MAX_EFBS],
    block_counter: [0; MAX_EFBS],
};

const ZERO_FRAME: TrapFrame = TrapFrame {
    regs: [0; 32],
    mepc: 0,
    mcause: 0,
    mtval: 0,
    mstatus: 0,
};

struct State {
    slots: [Slot; MAX_ENCLAVES],
    next_id: u32,
    current: Option<usize>,
    host_ctx: TrapFrame,
    host_ctx_valid: bool,
}

impl State {
    const fn new() -> Self {
        State {
            slots: [EMPTY_SLOT; MAX_ENCLAVES],
            next_id: 1, // ids start at 1 (host reserves 0 as empty-slot sentinel)
            current: None,
            host_ctx: ZERO_FRAME,
            host_ctx_valid: false,
        }
    }
}

use core::cell::UnsafeCell;
struct Kernel(UnsafeCell<State>);
// SAFETY: single-hart, cooperative; the trap handler is the only accessor.
unsafe impl Sync for Kernel {}
static KERNEL: Kernel = Kernel(UnsafeCell::new(State::new()));

fn state() -> &'static mut State {
    // SAFETY: sole accessor in a cooperative single-hart handler.
    unsafe { &mut *KERNEL.0.get() }
}

/// One-time kernel init (called from `init_kernel`). Mirrors the STM32 boot's
/// `Kernel::init` slot; the software crypto engine has no state to set up here.
pub fn init() {}

/// Install the **host-world** PMP context: the host region RWX (slot 3), the
/// enclave-stack entry disabled (slot 5). The ESS region is then uncovered, so
/// the S-mode host is PMP-denied the decrypted enclave — the key S>U fence.
pub fn enter_host_world() {
    let _ = pmp::set_tor(
        3,
        &Region::new(HOST_REGION_BASE, HOST_WORLD_END),
        PmpCfg::new().rwx(),
    );
    // Carve the CLINT mtimecmp word (hart 0: [0x0200_4000,0x0200_4008)) out of the
    // guest's low-MMIO grant so its writes fault into the vtimer. Region A below
    // mtimecmp, region B above it through the rest of low MMIO. Slots 4/6 are the
    // TOR bases (cfg stays OFF); slot 5 is reinstalled as the enclave stack on
    // enclave entry, slot 7 (region B) is inert for U (sPMP-gated).
    let _ = pmp::set_tor(5, &Region::new(0x0, 0x0200_4000), PmpCfg::new().rwx());
    let _ = pmp::set_tor(
        7,
        &Region::new(0x0200_4008, 0x2000_0000),
        PmpCfg::new().rwx(),
    );
    // Reflect the guest's timer + external interrupts: enable the machine
    // timer/external sources in `mie`. While the hart runs in S/U (the guest, the
    // enclave) machine interrupts are taken *unconditionally* — `mstatus.MIE` gates
    // only M-mode itself — so `mie.{MTIE,MEIE}` is all that is needed to make a
    // guest-bound IRQ trap into Umbra and be reflected (the same rule the enclave
    // preemption timer already relies on; see platform_impl::timer). We deliberately
    // do NOT set `mstatus.MIE`: the monitor is cooperative and must never take an
    // interrupt while in M-mode. QEMU resets `mtimecmp` to 0, so `MTIP` is pending
    // from boot; setting `mstatus.MIE` would fire a timer trap *inside* the M-mode
    // monitor during init_security, whose trap entry assumes traps come only from
    // S/U. Inert for the bare-metal host (it drives no timer/PLIC), so the enclave
    // regression is unaffected.
    // SAFETY: sets two architecturally-defined mie bits (MTIE=7, MEIE=11).
    unsafe { core::arch::asm!("csrs mie, {b}", b = in(reg) (1u32 << 7) | (1u32 << 11)) };
    // sPMP: the enclave's entries 0/1 must not govern the guest's U-tasks; the
    // guest's own shadow entries (2+) come back.
    spmp::disable_entry(0);
    spmp::disable_entry(1);
    paravirt::reinstall_shadow();
}

/// Install the **enclave-world** PMP context: ESS code R-X (slot 3) and the
/// enclave stack R-W (slot 5). The host region is then uncovered, so the U-mode
/// enclave is PMP-denied the host's memory.
pub fn enter_enclave_world() {
    let _ = pmp::set_tor(
        3,
        &Region::new(ESS_BASE, ESS_CODE_END),
        PmpCfg::new().r().x(),
    );
    let _ = pmp::set_tor(
        5,
        &Region::new(ENC_STACK_BASE, ENC_STACK_TOP),
        PmpCfg::new().r().w(),
    );
    // On the SPMP-patched QEMU every U/S access is checked against PMP AND sPMP,
    // and U-mode is denied-by-default unless an sPMP rule grants it. Delegate
    // rules and grant the U-mode enclave its code (R-X) and stack (R-W). The host
    // region has no U-mode sPMP rule, so the enclave stays fenced out of it —
    // defence-in-depth with the PMP swap. (The S-mode host is not gated by sPMP;
    // its fence is purely PMP.)
    //
    // mpmpdeleg is load-bearing twice and is now set once at boot (not here):
    // (a) num_deleg_rules = 64-32 = 32 so sPMP entries 0/1 are delegated/active;
    // (b) it also clamps the PMP enforcement window (max_pmp_index) past our
    // highest PMP slot (5) and the .text lock — see init_security_impl.
    // The guest's UMODE shadow entries must not govern the enclave U-task.
    paravirt::disable_shadow();
    spmp::write_napot_entry(
        0,
        ESS_BASE,
        ESS_CODE_END - ESS_BASE,
        cfg_bits::UMODE | cfg_bits::R | cfg_bits::X,
    );
    spmp::write_napot_entry(
        1,
        ENC_STACK_BASE,
        ENC_STACK_TOP - ENC_STACK_BASE,
        cfg_bits::UMODE | cfg_bits::R | cfg_bits::W,
    );
}

// ── Submodules (split to keep each file under the 600-LOC hard cap) ──────────
mod create;
mod ess_miss;
mod interrupt;
mod paravirt;
mod vtimer;

pub use create::create;
pub use ess_miss::try_handle_ess_miss;
pub use interrupt::{inject_guest_irq, try_handle_mret};
pub use paravirt::try_handle_paravirt_csr;
pub use vtimer::{emulate_access as vtimer_emulate, guest_due as vtimer_guest_due, is_mtimecmp};

/// Enter enclave `id`: snapshot the host context, then run the enclave in
/// U-mode. A **fresh** enclave starts at its entry point with the return
/// sentinel in `ra`; a **suspended** one (preempted earlier) resumes from its
/// saved context verbatim. Either way the preemption time-slice is armed so the
/// monitor regains control after one quantum.
pub fn enter(frame: &mut TrapFrame, id: u32) {
    let st = state();
    let idx = id as usize;
    if idx >= MAX_ENCLAVES || !st.slots[idx].used {
        frame.regs[10] = 0xFFFF_FFFF; // a0 = error
        frame.mepc += 4;
        return;
    }

    let mut saved = *frame;
    saved.mepc += 4; // resume the host after its `enter` ecall
    st.host_ctx = saved;
    st.host_ctx_valid = true;
    st.current = Some(idx);

    // Swap to the enclave-world PMP context before running the enclave (U-mode):
    // grants ESS code + enclave stack, revokes the host region.
    enter_enclave_world();

    if st.slots[idx].suspended {
        // Resume: restore the preempted register file + mepc + mstatus (MPP=U)
        // exactly as captured at the tick, so the enclave continues mid-stream.
        *frame = st.slots[idx].saved_ctx;
        st.slots[idx].suspended = false;
    } else {
        // Fresh start: jump to the entry point in U-mode with the return
        // sentinel in `ra` and the enclave stack in `sp`.
        frame.mepc = st.slots[idx].descriptor.entry_point;
        frame.regs[1] = RETURN_SENTINEL; // ra
        frame.regs[2] = ENC_SP; // sp
        frame.return_to_user();
    }

    // Arm the preemption tick for this slice. Disabled again the moment the
    // enclave suspends or terminates, so the host scheduler runs un-preempted.
    timer::arm();
    timer::enable();
}

/// Machine-timer-interrupt handler: if an enclave is running, snapshot its full
/// context into its slot, disable the timer, and hand the slice back to the host
/// (the scheduler) with status SUSPENDED so it can re-enter to resume. Returns
/// `false` if no enclave was current (a stray tick while the host ran) — the
/// caller then just disables the timer. This is the RISC-V counterpart of
/// L552's SysTick preemption + PSP context save.
pub fn try_preempt(frame: &mut TrapFrame) -> bool {
    let st = state();
    if let Some(idx) = st.current {
        st.slots[idx].saved_ctx = *frame; // full enclave context (regs + mepc + mstatus)
        st.slots[idx].suspended = true;
        timer::disable();
        // Re-enter host-world PMP before resuming the S-mode host.
        enter_host_world();
        st.current = None;
        if st.host_ctx_valid {
            *frame = st.host_ctx;
            frame.regs[10] = STATUS_SUSPENDED << 8; // a0 = packed SUSPENDED status
            st.host_ctx_valid = false;
        }
        true
    } else {
        false
    }
}

/// True when a trap is the active enclave returning to the sentinel. If so the
/// monitor completes the enclave (storing the result, resuming the host) and
/// returns `true`.
pub fn try_handle_return(frame: &mut TrapFrame) -> bool {
    let st = state();
    if st.current.is_some() && frame.mepc == RETURN_SENTINEL {
        let result = frame.regs[10]; // a0 = enclave's return value
        complete(frame, result);
        true
    } else {
        false
    }
}

/// Complete the current enclave: store its result and resume the host with the
/// packed `(STATUS_TERMINATED << 8) | (result & 0xFF)` in `a0`. Also used by an
/// enclave that opts to signal completion via the `exit` ecall.
pub fn complete(frame: &mut TrapFrame, result: u32) {
    // Re-enter host-world PMP before resuming the S-mode host.
    enter_host_world();
    let st = state();
    // The enclave is done — no more preemption ticks for it.
    timer::disable();
    if let Some(idx) = st.current.take() {
        st.slots[idx].result = result;
    }
    if st.host_ctx_valid {
        *frame = st.host_ctx;
        frame.regs[10] = (STATUS_TERMINATED << 8) | (result & 0xFF);
        st.host_ctx_valid = false;
    }
}

/// Return the full result word of a terminated enclave (the `status` ecall).
pub fn status(id: u32) -> u32 {
    let st = state();
    let idx = id as usize;
    if idx < MAX_ENCLAVES && st.slots[idx].used {
        st.slots[idx].result
    } else {
        0xFFFF_FFFF
    }
}
