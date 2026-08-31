//! NSC implementations for remote attestation (`umbra_attest_quote`) and secure
//! enclave update (`umbra_enclave_update`). Called by the veneers in
//! kernel/asm/arm/nsc_veneers.s. Pointers from NS are untrusted and range-checked
//! into the NS AXISRAM host window before any dereference. The update half
//! (`umbra_enclave_update_imp`) is added in a later task.

use kernel::key_storage_server::attestation::{build_quote, QuoteFields, QUOTE_LEN};
// `AnchorStore` brings the `.load()` method into scope for `read_anchor_gen` (always used).
use kernel::key_storage_server::state_checkpoint::AnchorStore;
// `MonotonicCounter` brings `.floor()` into scope; only used under the version-bind build.
#[cfg_attr(not(feature = "enclave_version_bind"), allow(unused_imports))]
use kernel::key_storage_server::version_search::MonotonicCounter;

use kernel::key_storage_server::enclave_update::{parse_and_verify, select_active_slot, UpdateError};

use kernel::common::enclave::EnclaveState;

use crate::secure_kernel::Kernel;

/// NS host RAM window (AXISRAM3_NS): pointers from NS must fall inside this.
const NS_RAM_LO: u32 = 0x2400_0000;
const NS_RAM_HI: u32 = 0x2410_0000;

/// True iff `[ptr, ptr+len)` is entirely inside the NS host RAM window (overflow-safe).
pub(crate) fn ns_range_ok(ptr: u32, len: u32) -> bool {
    match ptr.checked_add(len) {
        Some(end) => ptr >= NS_RAM_LO && end <= NS_RAM_HI,
        None => false,
    }
}

// Secure USART1 (0x5200_1000). USART1 stays Secure (RIFSC leaves it so), so the NS
// attestation relay cannot poll RX/TX directly — it goes through the bridge veneers
// below. RE is enabled in power::init_uart.
const UART_BASE: u32 = 0x5200_1000;
const UART_ISR: u32 = 0x1C;
const UART_ICR: u32 = 0x20;
const UART_RDR: u32 = 0x24;
const UART_TDR: u32 = 0x28;
const ISR_RXNE: u32 = 1 << 5;
const ISR_ORE: u32 = 1 << 3;
const ICR_ORECF: u32 = 1 << 3;

/// Per-byte RX timeout (poll iterations). At 800 MHz this is ~10 ms — far longer than
/// the ~87 µs between bytes at 115200, so an in-flight frame never times out, but a
/// stalled/misaligned read (e.g. a spurious length from boot-window overrun bytes)
/// returns instead of wedging the relay forever.
const RX_TIMEOUT_SPINS: u32 = 2_000_000;

/// Poll RXNE with a timeout, clearing overrun (ORE) as it appears. Returns the byte
/// (0..255) or -1 on timeout. On this USART IP a latched ORE stops further RXNE from
/// setting, so clearing ORECF (ICR bit 3) each iteration keeps the receiver alive
/// (HW-confirmed 2026-07-14: ISR=0x006000d8 = ORE set, RXNE clear). SAFETY: fixed
/// Secure USART1 MMIO.
fn uart_rx_byte_timeout() -> i32 {
    unsafe {
        let mut spins = 0u32;
        loop {
            let isr = core::ptr::read_volatile((UART_BASE + UART_ISR) as *const u32);
            if isr & ISR_ORE != 0 {
                core::ptr::write_volatile((UART_BASE + UART_ICR) as *mut u32, ICR_ORECF);
            }
            if isr & ISR_RXNE != 0 {
                return (core::ptr::read_volatile((UART_BASE + UART_RDR) as *const u32) & 0xFF)
                    as i32;
            }
            spins += 1;
            if spins > RX_TIMEOUT_SPINS {
                return -1;
            }
        }
    }
}

fn uart_tx_byte(b: u8) {
    // SAFETY: fixed Secure USART1 MMIO; blocking poll of TXE (ISR bit 7).
    unsafe {
        while core::ptr::read_volatile((UART_BASE + UART_ISR) as *const u32) & (1 << 7) == 0 {}
        core::ptr::write_volatile((UART_BASE + UART_TDR) as *mut u32, b as u32);
    }
}

/// Secure UART bridge — read UP TO `len` bytes into the NS buffer `ptr`, each with a
/// per-byte timeout. r0 = NS pointer, r1 = length. **Returns the COUNT of bytes actually
/// read** (< len on timeout, 0 on a bad pointer). The NS relay uses the count to
/// resync: a short read means the frame stalled (e.g. a spurious length parsed from
/// boot-window overrun bytes) so it drops the frame instead of wedging. Tightly scoped:
/// it only moves raw bytes into a range-checked NS buffer, so the relay (which owns the
/// frame parser) keeps the "NS = only DoS" property.
#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_uart_read_imp(ptr: u32, len: u32) -> u32 {
    if !ns_range_ok(ptr, len) {
        return 0;
    }
    let mut i = 0u32;
    while i < len {
        let b = uart_rx_byte_timeout();
        if b < 0 {
            break; // timeout: return the partial count so the relay can resync
        }
        // SAFETY: [ptr, ptr+len) range-checked into NS RAM above.
        unsafe { core::ptr::write_volatile((ptr as *mut u8).add(i as usize), b as u8) };
        i += 1;
    }
    i
}

/// Secure UART bridge — write `len` bytes from the NS buffer `ptr` to Secure USART1.
/// r0 = NS pointer, r1 = length. Returns 0, or 0xFFFF_FFF6 on a bad pointer.
#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_uart_write_imp(ptr: u32, len: u32) -> u32 {
    if !ns_range_ok(ptr, len) {
        return 0xFFFF_FFF6;
    }
    let mut i = 0u32;
    while i < len {
        // SAFETY: [ptr, ptr+len) range-checked into NS RAM above.
        let b = unsafe { core::ptr::read_volatile((ptr as *const u8).add(i as usize)) };
        uart_tx_byte(b);
        i += 1;
    }
    0
}

/// System reset (SYSRESETREQ). The NS relay calls this after a successful update so
/// the device reboots into the new slot WITHOUT a manual reset — `create(0)` at boot
/// selects the higher-version slot (MCUboot/OTA activate-on-reboot model). A software
/// reset preserves the TAMP backup domain, so the anti-rollback floor carries over.
/// Waits for the UART TX to fully drain (TC) first so the final `UPDATE_RESP` byte
/// reaches the host before the line drops. Never returns.
#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_system_reset_imp() -> u32 {
    const ISR_TC: u32 = 1 << 6; // transmission complete
    const SCB_AIRCR: *mut u32 = 0xE000_ED0C as *mut u32;
    // SAFETY: fixed Secure USART1 + SCB MMIO.
    unsafe {
        // Bounded drain: don't hang if TC never sets.
        let mut spins = 0u32;
        while core::ptr::read_volatile((UART_BASE + UART_ISR) as *const u32) & ISR_TC == 0 {
            spins += 1;
            if spins > 10_000_000 {
                break;
            }
        }
        cortex_m::asm::dsb();
        // VECTKEY 0x05FA<<16 | SYSRESETREQ (bit 2). Secure SCB alias.
        core::ptr::write_volatile(SCB_AIRCR, (0x05FA << 16) | (1 << 2));
        cortex_m::asm::dsb();
        loop {
            cortex_m::asm::nop();
        }
    }
}

/// HW HMAC-SHA256 over the flattened parts. Both defined tags now pass exactly one
/// contiguous part (quote = 83 bytes; update = 91 bytes, built flat by the crate's
/// `compute_pkg_tag`), so the `parts.len() == 1` fast path is what runs. The
/// multi-part flatten below is a bounded-scratch fallback (sized 128 to cover both
/// with margin) with a keyed, fail-closed overflow guard; it is dead for the two
/// defined tags but kept so no future multi-part caller can silently overflow.
pub(crate) fn hw_hmac_single(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = drivers::hash::Hash::new();
    let mut out = [0u8; 32];
    if parts.len() == 1 {
        hash.hmac_sha256(key, parts[0], &mut out);
    } else {
        let mut buf = [0u8; 128];
        let mut n = 0usize;
        for p in parts {
            if n + p.len() > buf.len() {
                // Preimage longer than the fixed scratch — must not happen for the
                // defined tags (quote 83, update 91). Returning a CONSTANT here
                // (the old code returned all zeros, "a zero tag will never match a
                // real HMAC") would be fail-OPEN, not fail-closed: this value is
                // compared by `ct_eq32(&expect, got)` against 32 bytes taken
                // verbatim from the ATTACKER-SUPPLIED package, so an attacker who
                // writes that same constant into the tag field is accepted.
                // Return a KEYED, domain-separated value instead: unpredictable
                // without `key`, so no attacker-chosen tag can match it, and no
                // panic/reset in the middle of an update handler.
                let mut poison = [0u8; 32];
                hash.hmac_sha256(key, b"umbra-hmac-overflow", &mut poison);
                return poison;
            }
            buf[n..n + p.len()].copy_from_slice(p);
            n += p.len();
        }
        hash.hmac_sha256(key, &buf[..n], &mut out);
    }
    out
}

// --- DWT cycle counter (bench telemetry only). CPU @ 800 MHz; CYCCNT is 32-bit so
// it wraps at ~5.4 s — every measured phase is far shorter, deltas use wrapping_sub.
const DWT_CYCCNT: *const u32 = 0xE000_1004 as *const u32;

/// Enable TRCENA + CYCCNTENA (idempotent) and return the current cycle count.
fn cyccnt_start() -> u32 {
    // SAFETY: fixed CoreDebug DEMCR + DWT MMIO.
    unsafe {
        let demcr = 0xE000_EDFC as *mut u32;
        core::ptr::write_volatile(demcr, core::ptr::read_volatile(demcr) | (1 << 24));
        let ctrl = 0xE000_1000 as *mut u32;
        core::ptr::write_volatile(ctrl, core::ptr::read_volatile(ctrl) | 1);
        core::ptr::read_volatile(DWT_CYCCNT)
    }
}

fn cyccnt() -> u32 {
    // SAFETY: fixed DWT MMIO, read-only.
    unsafe { core::ptr::read_volatile(DWT_CYCCNT) }
}

/// Read the current HDPL code (low byte of BSEC_HDPLSR).
fn read_hdpl() -> u8 {
    // SAFETY: BSEC_HDPLSR is valid Secure MMIO (CMSIS BSEC_BASE_S + 0xE94).
    let raw = unsafe { core::ptr::read_volatile(0x5600_9E94 as *const u32) };
    (raw & 0xFF) as u8
}

/// State-continuity anchor generation (0 if cold/absent).
fn read_anchor_gen() -> u32 {
    drivers::state_anchor::StateAnchor::new()
        .load()
        .map(|a| a.generation)
        .unwrap_or(0)
}

/// Gather (author_id, floor, flags-bit0) for the quote. author_id/floor exist only when
/// the version-bind feature is on; flags bit0 mirrors that so the verifier can tell.
fn gather_version_state() -> (u32, u32, u32) {
    #[cfg(feature = "enclave_version_bind")]
    {
        let author_id = crate::secure_kernel::AUTHOR_ID;
        let floor = crate::antirollback::BackupFloorCounter::new().floor(author_id);
        (author_id, floor, 0x1)
    }
    #[cfg(not(feature = "enclave_version_bind"))]
    {
        (0, 0, 0x0)
    }
}

/// Map a running enclave id to its context index via the ESS loaded_enclaves table.
fn current_enclave_idx(kernel: &Kernel, id: u32) -> Option<usize> {
    for (i, slot) in kernel.ess.loaded_enclaves.iter().enumerate() {
        if let Some(le) = slot {
            if le.descriptor.id == id {
                return Some(i);
            }
        }
    }
    None
}

/// Current enclave id + its status discriminant (0, 0 if none loaded).
fn gather_enclave_state(kernel: &Kernel) -> (u32, u8) {
    match kernel.current_enclave_id {
        Some(id) => match current_enclave_idx(kernel, id) {
            Some(idx) => (id, kernel.enclave_contexts[idx].status as u8),
            None => (id, 0),
        },
        None => (0, 0),
    }
}

/// Build and sign an attestation quote. r0 = NS pointer to a 16-byte nonce, r1 = NS
/// pointer to a QUOTE_LEN-byte output buffer. Returns 0 on success, 0xFFFF_FFF6 on a
/// bad pointer, 0xFFFF_FFFE if the kernel is missing. Arms the nonce for a subsequent
/// single-use update.
#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_attest_quote_imp(nonce_ptr: u32, out_ptr: u32) -> u32 {
    if !ns_range_ok(nonce_ptr, 16) || !ns_range_ok(out_ptr, QUOTE_LEN as u32) {
        return 0xFFFF_FFF6;
    }
    let kernel = match unsafe { Kernel::get() } {
        Some(k) => k,
        None => return 0xFFFF_FFFE,
    };

    let t0 = cyccnt_start();
    let mut nonce = [0u8; 16];
    // SAFETY: nonce_ptr range-checked into NS RAM above.
    unsafe {
        for i in 0..16 {
            nonce[i] = core::ptr::read_volatile((nonce_ptr as *const u8).add(i));
        }
    }

    let (author_id, floor, flags) = gather_version_state();
    let (enclave_id, status) = gather_enclave_state(kernel);

    let q = QuoteFields {
        nonce,
        enclave_id,
        status,
        bm: kernel.chain_state,
        author_id,
        version: kernel.last_version,
        floor,
        anchor_gen: read_anchor_gen(),
        restore: kernel.last_restore,
        reset_cause: kernel.reset_cause,
        hdpl: read_hdpl(),
        flags,
    };

    let mut out = [0u8; QUOTE_LEN];
    let key = kernel.attest_key;
    build_quote(&q, &key, hw_hmac_single, &mut out);
    let t1 = cyccnt();

    // SAFETY: out_ptr range-checked into NS RAM above.
    unsafe {
        for i in 0..QUOTE_LEN {
            core::ptr::write_volatile((out_ptr as *mut u8).add(i), out[i]);
        }
    }
    // Bench telemetry: quote generation cost (gather + HW HMAC), 8-digit hex cycles.
    // Printed after the out-buffer write so it never delays the measured section; the
    // ~3 ms of UART print time DOES sit inside the host-observed round-trip.
    crate::raw_print::print_str("[UMBRA-BENCH] quote cyc=");
    crate::raw_print::print_hex(t1.wrapping_sub(t0));
    crate::raw_print::print_str("\r\n");
    kernel.last_nonce = nonce;
    kernel.nonce_armed = true;
    0
}

// ---------------------------------------------------------------------------
// Secure enclave update (`umbra_enclave_update`).
// ---------------------------------------------------------------------------

// Update status codes (0xFFFF_FF2* space, distinct from the create nsc_status set).
const ERR_NONCE: u32 = 0xFFFF_FF20; // no armed nonce / nonce mismatch
const ERR_AUTH: u32 = 0xFFFF_FF21; // pkg_tag invalid
const ERR_VERIFY: u32 = 0xFFFF_FF22; // written slot fails measurement
const ERR_ROLLBACK: u32 = 0xFFFF_FF23; // written version <= active version
const ERR_FLASH: u32 = 0xFFFF_FF24; // flash write failed
const ERR_BUSY: u32 = 0xFFFF_FF25; // a loaded enclave has not finished running
const ERR_ARG: u32 = 0xFFFF_FFF6; // bad pointer/length or malformed package

/// Secure scratch for the received update package (.bss, zero-init). 64 KB bounds
/// the largest package (blob <= ~24 KB + framing). A const-init static would blow
/// .rodata — keep it .bss.
static mut PKG_SCRATCH: [u8; 0x10000] = [0u8; 0x10000];

/// Install a remotely-sent enclave into the inactive A/B slot. r0 = NS pointer to the
/// update package, r1 = package length. Returns 0 on success or an ERR_* code. The
/// armed nonce is CONSUMED on every path once a nonce was in play (success or failure).
/// The re-verification probe (`authenticated_version_at`) is DMA-free and reads flash
/// directly, so this handler COEXISTS with `interenclave_overlay` (the default feature).
#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_enclave_update_imp(pkg_ptr: u32, pkg_len: u32) -> u32 {
    // 32 prefix + 48 min blob + 32 tag = 112 minimum; cap at the scratch size.
    if !ns_range_ok(pkg_ptr, pkg_len) || pkg_len < 112 || pkg_len as usize > 0x10000 {
        return ERR_ARG;
    }
    let t0 = cyccnt_start();

    // Capture the armed nonce + key, then DISARM and drop the kernel borrow before any
    // `authenticated_version_at` call (that probe takes its own `&'static mut Kernel`;
    // holding one here would alias). Nothing below re-touches `kernel`.
    let (expected, key) = {
        let kernel = match unsafe { Kernel::get() } {
            Some(k) => k,
            None => return 0xFFFF_FFFE,
        };
        if !kernel.nonce_armed {
            return ERR_NONCE;
        }
        // Consume the arm up-front: any outcome disarms (single-use nonce).
        kernel.nonce_armed = false;
        // Quiescence interlock: refuse while any loaded enclave could still run. The
        // probes below re-borrow the kernel and clobber `chain_state` (the bm a later
        // quote reports), and under `interenclave_overlay` + SysTick an enclave could
        // be mid-execution when NS calls in — updating then would be an untested
        // re-entrancy/consistency hazard. Only Terminated/Faulted enclaves are inert.
        for (i, slot) in kernel.ess.loaded_enclaves.iter().enumerate() {
            if slot.is_some()
                && !matches!(
                    kernel.enclave_contexts[i].status,
                    EnclaveState::Terminated | EnclaveState::Faulted
                )
            {
                return ERR_BUSY;
            }
        }
        (kernel.last_nonce, kernel.update_key)
    };

    // Copy the package from untrusted NS memory into the Secure scratch ONCE, then
    // operate only on the Secure copy (NS memory could change under us = TOCTOU).
    let len = pkg_len as usize;
    // SAFETY: pkg_ptr..pkg_ptr+len range-checked into NS RAM; PKG_SCRATCH is Secure .bss.
    let pkg: &[u8] = unsafe {
        let dst = core::ptr::addr_of_mut!(PKG_SCRATCH) as *mut u8;
        for i in 0..len {
            core::ptr::write_volatile(
                dst.add(i),
                core::ptr::read_volatile((pkg_ptr as *const u8).add(i)),
            );
        }
        core::slice::from_raw_parts(dst, len)
    };
    let t_copy = cyccnt();

    // Authenticate: nonce binding + pkg_tag (over the Secure copy).
    let (author_id, version, blob_len) = match parse_and_verify(pkg, &expected, hw_hmac_single, &key)
    {
        Ok(v) => (v.author_id, v.version, v.blob.len()),
        Err(UpdateError::NonceMismatch) => return ERR_NONCE,
        Err(UpdateError::TagInvalid) => return ERR_AUTH,
        Err(_) => return ERR_ARG,
    };
    let _ = author_id; // (author binding is inside the tag; not needed further here)
    let t_auth = cyccnt();

    // Decide the inactive slot = NOT the current active-by-version slot. These probes take
    // their own kernel borrow — safe because we dropped ours above.
    let va = crate::api_impl::authenticated_version_at(drivers::state_flash::ENCLAVE_SLOT_A);
    let vb = crate::api_impl::authenticated_version_at(drivers::state_flash::ENCLAVE_SLOT_B);
    let active = select_active_slot(va, vb);
    let target_slot = match active {
        Some(0) => 1, // A active -> write B
        Some(1) => 0, // B active -> write A
        _ => 0,       // nothing valid yet -> write A
    };
    let active_version = match active {
        Some(0) => va,
        Some(1) => vb,
        _ => None,
    };
    let t_probe = cyccnt();

    // Move the blob to the front of the scratch and zero-pad to a whole 4 KB sector
    // (write_enclave_slot needs a %4096 buffer; un-erased NOR reads non-deterministically
    // so the pad MUST be deterministic zeros). The VerifiedUpdate borrow ended above; we
    // now own author/version/blob_len, so mutating the scratch is safe.
    const BLOB_OFF: usize = 32; // package: magic..blob_len = 32 bytes prefix
    let padded_len = (blob_len + 4095) & !4095;
    if padded_len > 0x10000 {
        return ERR_ARG;
    }
    // SAFETY: single-threaded Secure context; move-down within PKG_SCRATCH then zero the tail.
    let padded: &[u8] = unsafe {
        let base = core::ptr::addr_of_mut!(PKG_SCRATCH) as *mut u8;
        // memmove blob [BLOB_OFF .. BLOB_OFF+blob_len) down to [0 .. blob_len)
        core::ptr::copy(base.add(BLOB_OFF), base, blob_len);
        // zero-pad [blob_len .. padded_len)
        for i in blob_len..padded_len {
            core::ptr::write_volatile(base.add(i), 0);
        }
        core::slice::from_raw_parts(base, padded_len)
    };

    // Write the inactive slot.
    if drivers::state_flash::write_enclave_slot(target_slot, padded).is_err() {
        return ERR_FLASH;
    }
    let t_flash = cyccnt();

    // Re-verify FROM FLASH: authenticate the slot we just wrote, require version strictly
    // above the active slot. This reads the persisted bytes (not the NS blob) — closes the
    // TOCTOU and enforces anti-rollback at install time.
    let base = match drivers::state_flash::enclave_slot_base(target_slot) {
        Ok(b) => b,
        Err(_) => return ERR_FLASH,
    };
    let written = crate::api_impl::authenticated_version_at(base);
    let _ = version; // declared version is advisory; the authenticated one is authoritative
    let t_verify = cyccnt();

    // Bench telemetry: per-phase cycle deltas (8-digit uppercase hex, 800 MHz CPU).
    // Printed BEFORE the relay sends the response frame; the CLI resyncs on SOF so
    // this ASCII line never confuses the framed protocol.
    crate::raw_print::print_str("[UMBRA-BENCH] upd copy=");
    crate::raw_print::print_hex(t_copy.wrapping_sub(t0));
    crate::raw_print::print_str(" auth=");
    crate::raw_print::print_hex(t_auth.wrapping_sub(t_copy));
    crate::raw_print::print_str(" probe=");
    crate::raw_print::print_hex(t_probe.wrapping_sub(t_auth));
    crate::raw_print::print_str(" flash=");
    crate::raw_print::print_hex(t_flash.wrapping_sub(t_probe));
    crate::raw_print::print_str(" verify=");
    crate::raw_print::print_hex(t_verify.wrapping_sub(t_flash));
    crate::raw_print::print_str("\r\n");

    match (written, active_version) {
        (None, _) => {
            // Bad write / measurement mismatch: invalidate the slot's first sector so a
            // later create(0) never selects a corrupt image.
            let zero = [0u8; 4096];
            let _ = drivers::state_flash::write_enclave_slot(target_slot, &zero);
            ERR_VERIFY
        }
        (Some(w), Some(a)) if w <= a => ERR_ROLLBACK,
        (Some(_), _) => {
            // Fresh authenticated image in target_slot: reset its failed-boot counter so
            // the liveness fallback gives the new image a clean chance (the slot may have
            // held a crash-looping image that got excluded — see antirollback).
            #[cfg(feature = "enclave_version_bind")]
            crate::antirollback::BootFailCounter::new().clear(target_slot);
            0 // success — next create(0) selects the new higher-version slot
        }
    }
}
