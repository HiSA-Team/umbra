//! Enclave state-continuity: checkpoint/restore of a running enclave. Serializes the
//! `EnclaveContext` + PSP stack, AES-CTR encrypts, writes the flash state region, and
//! commits the double-buffered TAMP anchor with a root keyed by the stable `state_root`.
//! Restore verifies the root over the persisted flash, decrypts, and deserializes back.

use drivers::aes::AesEngine; // brings ctr_xform into scope
use drivers::state_anchor::StateAnchor;
use drivers::state_flash::{self, STATE_REGION_BASE};
use kernel::common::enclave::EnclaveContext;
use kernel::common::ess::{enclave_psp_top, ENCLAVE_PSP_STACK_SIZE};
use kernel::key_storage_server::state_checkpoint::{
    checkpoint, restore, AnchorStore, RestoreDecision, SectorStore,
};
use kernel::key_storage_server::state_continuity::STATE_SECTOR_SIZE;
use kernel::key_storage_server::state_root::ROOT_PREIMAGE_LEN;

/// Snapshot-layout version bound into the root (author-owned; bump on layout change).
const STATE_FMT: u32 = 1;
/// Raw bytes of one `EnclaveContext` (repr(C); checkpoint and restore are the same
/// build, so the layout is self-consistent).
const CTX_BYTES: usize = core::mem::size_of::<EnclaveContext>();
/// Plaintext snapshot = context bytes followed by the full PSP stack.
const SNAPSHOT_BYTES: usize = CTX_BYTES + ENCLAVE_PSP_STACK_SIZE as usize;
/// Sectors the snapshot occupies (rounded up); the remaining sectors are zero-filled
/// so every one of the 16 the root covers is in a known, deterministically-readable
/// state.
const SNAPSHOT_SECTORS: usize = (SNAPSHOT_BYTES + STATE_SECTOR_SIZE - 1) / STATE_SECTOR_SIZE;

// Plaintext/ciphertext scratch for the snapshot, sized to whole sectors. Static
// (.bss) — the FSBL stack is shallow, and a const-init static would blow .rodata.
// Word-aligned (via the wrapper) so the DMA-fed CTR (`ctr_xform`) can address it — HPDMA
// word transfers need a word-aligned base, and a bare `static [u8; N]` is align-1.
#[repr(C, align(4))]
struct SnapBuf([u8; SNAPSHOT_SECTORS * STATE_SECTOR_SIZE]);
static mut SNAP: SnapBuf = SnapBuf([0u8; SNAPSHOT_SECTORS * STATE_SECTOR_SIZE]);
// One reused sector page for staging to flash.
static mut PAGE: [u8; STATE_SECTOR_SIZE] = [0u8; STATE_SECTOR_SIZE];

/// CTR IV for an enclave's snapshot — fixed per enclave (id in bytes 0..4). v1
/// limitation: keystream reuse across checkpoints; a generation-derived nonce would fix it.
fn snapshot_iv(enclave_id: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&enclave_id.to_le_bytes());
    iv
}

/// AES-CTR transform (symmetric) with the CRYP-resident enc_key. Encrypt == decrypt.
fn aes_ctr(iv: &[u8; 16], data: &mut [u8]) {
    // enc_key was shared into CRYP over the SAES bus at boot; a fresh handle uses it.
    let mut aes = drivers::aes::AesHardware::new();
    aes.ctr_xform(iv, data);
}

/// Flash-backed store for enclave snapshots. `stage` writes sector `idx` from `SNAP`
/// (zero beyond the snapshot); `read_digest` hashes the committed flash slot.
struct EnclaveFlashStore;

impl SectorStore for EnclaveFlashStore {
    fn stage(&mut self, idx: usize, slot: usize) -> Result<(), ()> {
        // SAFETY: single-threaded Secure context; PAGE/SNAP are used only here.
        unsafe {
            let page = &mut *core::ptr::addr_of_mut!(PAGE);
            let start = idx * STATE_SECTOR_SIZE;
            if start < SNAPSHOT_SECTORS * STATE_SECTOR_SIZE {
                let snap = &(*core::ptr::addr_of!(SNAP)).0;
                page.copy_from_slice(&snap[start..start + STATE_SECTOR_SIZE]);
            } else {
                page.fill(0);
            }
            state_flash::write_state_sector(idx, slot, page).map_err(|_| ())
        }
    }

    fn read_digest(&self, idx: usize, slot: usize) -> [u8; 32] {
        let addr = state_flash::state_sector_addr(idx, slot).unwrap_or(STATE_REGION_BASE);
        state_flash::invalidate_dcache_region(addr, STATE_SECTOR_SIZE as u32);
        // SAFETY: bounds-checked address in the mapped XSPI2 window; read-only.
        let bytes: &[u8] =
            unsafe { core::slice::from_raw_parts(addr as *const u8, STATE_SECTOR_SIZE) };
        let mut hash = drivers::hash::Hash::new();
        let mut out = [0u8; 32];
        // HW HASH fed by HPDMA1: the root covers 16 × 4 KB sectors, so DMA-feeding
        // offloads ~1 K CPU word-writes per sector (HW-verified byte-identical to the CPU
        // path — see the flash cross-check in dhuk_provision). Firmware-only; boot is arm.
        hash.sha256_dma(bytes, &mut out);
        out
    }
}

/// Keyed HMAC-SHA256 root primitive (matches `compute_root`'s `FnOnce`): flatten the
/// parts into one buffer for the HW HMAC. Keyed by `state_root`.
fn hw_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = [0u8; ROOT_PREIMAGE_LEN];
    let mut n = 0;
    for p in parts {
        buf[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    let mut hash = drivers::hash::Hash::new();
    let mut out = [0u8; 32];
    hash.hmac_sha256(key, &buf[..n], &mut out);
    out
}

/// Serialize `ctx` + the enclave's PSP stack into `SNAP` (plaintext), then AES-CTR
/// encrypt in place. `enclave_idx` selects the PSP stack region.
///
/// SAFETY: reads `ENCLAVE_PSP_STACK_SIZE` bytes from the enclave's PSP stack region,
/// which the caller guarantees is mapped and belongs to this enclave.
unsafe fn serialize_and_encrypt(enclave_id: u32, enclave_idx: usize, ctx: &EnclaveContext) {
    let snap = &mut (*core::ptr::addr_of_mut!(SNAP)).0;
    // context raw bytes
    let ctx_bytes = core::slice::from_raw_parts(ctx as *const _ as *const u8, CTX_BYTES);
    snap[..CTX_BYTES].copy_from_slice(ctx_bytes);
    // PSP stack bytes
    let stack_base = enclave_psp_top(enclave_idx) - ENCLAVE_PSP_STACK_SIZE;
    let stack = core::slice::from_raw_parts(stack_base as *const u8, ENCLAVE_PSP_STACK_SIZE as usize);
    snap[CTX_BYTES..SNAPSHOT_BYTES].copy_from_slice(stack);
    // zero the tail up to the sector boundary (deterministic padding)
    for b in snap[SNAPSHOT_BYTES..].iter_mut() {
        *b = 0;
    }
    let iv = snapshot_iv(enclave_id);
    aes_ctr(&iv, &mut snap[..SNAPSHOT_SECTORS * STATE_SECTOR_SIZE]);
}

/// Checkpoint the enclave: serialize + encrypt + write flash + commit the anchor
/// keyed by `state_root`. Returns true on success.
pub fn checkpoint_enclave(
    enclave_id: u32,
    enclave_idx: usize,
    ctx: &EnclaveContext,
    state_root: &[u8; 32],
) -> bool {
    // SAFETY: Secure single-threaded context; SNAP filled here before use.
    unsafe { serialize_and_encrypt(enclave_id, enclave_idx, ctx) };
    let mut store = EnclaveFlashStore;
    let mut anchor = StateAnchor::new();
    checkpoint(&mut store, &mut anchor, 0xFFFF, state_root, enclave_id, STATE_FMT, hw_hmac).is_ok()
}

/// Restore the enclave state from flash. On `Resume`, decrypt and deserialize the
/// snapshot back into `ctx` and the enclave's PSP stack, and return true. On
/// `Reject`/`ColdGenesis`, leave `ctx` untouched and return false.
pub fn restore_enclave(
    enclave_id: u32,
    enclave_idx: usize,
    ctx: &mut EnclaveContext,
    state_root: &[u8; 32],
) -> bool {
    let store = EnclaveFlashStore;
    let anchor = StateAnchor::new();
    match restore(&store, &anchor, state_root, enclave_id, STATE_FMT, hw_hmac) {
        RestoreDecision::Resume => {}
        RestoreDecision::Reject | RestoreDecision::ColdGenesis => return false,
    }
    // SAFETY: Secure single-threaded context; reads the committed flash into SNAP,
    // decrypts, and writes the enclave's own context + PSP stack.
    unsafe {
        let snap = &mut (*core::ptr::addr_of_mut!(SNAP)).0;
        // read the committed ciphertext from flash into SNAP
        let a = match StateAnchor::new().load() {
            Some(a) => a,
            None => return false,
        };
        let mut s = 0;
        while s < SNAPSHOT_SECTORS {
            let slot = ((a.parity >> s) & 1) as usize;
            let addr = match state_flash::state_sector_addr(s, slot) {
                Ok(x) => x,
                Err(_) => return false,
            };
            state_flash::invalidate_dcache_region(addr, STATE_SECTOR_SIZE as u32);
            let src = core::slice::from_raw_parts(addr as *const u8, STATE_SECTOR_SIZE);
            snap[s * STATE_SECTOR_SIZE..(s + 1) * STATE_SECTOR_SIZE].copy_from_slice(src);
            s += 1;
        }
        // decrypt
        let iv = snapshot_iv(enclave_id);
        aes_ctr(&iv, &mut snap[..SNAPSHOT_SECTORS * STATE_SECTOR_SIZE]);
        // deserialize context
        let ctx_dst = core::slice::from_raw_parts_mut(ctx as *mut _ as *mut u8, CTX_BYTES);
        ctx_dst.copy_from_slice(&snap[..CTX_BYTES]);
        // deserialize PSP stack
        let stack_base = enclave_psp_top(enclave_idx) - ENCLAVE_PSP_STACK_SIZE;
        let stack = core::slice::from_raw_parts_mut(stack_base as *mut u8, ENCLAVE_PSP_STACK_SIZE as usize);
        stack.copy_from_slice(&snap[CTX_BYTES..SNAPSHOT_BYTES]);
    }
    true
}
