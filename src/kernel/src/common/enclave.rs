//////////////////////////////////////////////////////////////////////////////////////
// //
// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it> //
// Description: //
// Enclave data structures and header definitions //
// //
//////////////////////////////////////////////////////////////////////////////////////

// Alias to the single-source-of-truth SLOT_SIZE in ess.rs (Stage A
// Step 1: build-time knob via.cargo/config.toml [env]). The previous
// hardcoded 256 was duplicated; keeping the alias preserves callers.
pub use crate::common::ess::SLOT_SIZE as EFB_SIZE;
pub const UMBRA_HEADER_SIZE: u32 = 48;

#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum EnclaveTrustLevel {
    Untrusted = 0,
    Trusted = 1,
}

/// Header EFB
/// ```text
/// +---------------------------+
/// | magic (4 bytes) |
/// +---------------------------+
/// | trust_level (1 byte) |
/// +---------------------------+
/// | reserved (1 byte) |
/// +---------------------------+
/// | efbc_size (2 bytes) |
/// +---------------------------+
/// | ess_blocks (2 bytes) |
/// +---------------------------+
/// | code_size (4 bytes) | encrypted blocks only, NOT incl. reloc table
/// +---------------------------+
/// | reloc_count (2 bytes) | static-PIE R_ARM_ABS32 reloc entries
/// +---------------------------+ appended after the encrypted blocks
/// | hmac (32 bytes) |
/// +---------------------------+
/// ```
/// On-flash blob layout (post protect_enclave.py):
/// [0..48): this header
/// [48..48+code_size): `code_size / TOTAL_BLOCK_SIZE` encrypted blocks
/// [48+code_size..48+code_size+4*N): `N == reloc_count` u32 plaintext-relative
/// byte offsets, each marking a 32-bit slot
/// to be patched with the runtime-delta on
/// block install (see secure_kernel.rs).
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct UmbraEnclaveHeader {
    pub magic: u32,
    pub trust_level: u8,
    pub reserved0: u8,
    pub efbc_size: u16,
    pub ess_blocks: u16,
    pub code_size: u32,
    /// Number of `R_ARM_ABS32` reloc offsets appended after the encrypted
    /// blocks. The kernel reads exactly this many u32 entries starting at
    /// `header_flash_base + UMBRA_HEADER_SIZE + code_size`. Each entry is
    /// a plaintext-relative byte offset of a 32-bit word to be rewritten
    /// post-AES-decrypt: `*(u32*)slot += runtime_base - 0x30`.
    pub reloc_count: u16,
    pub hmac: [u8; 32],
}

impl UmbraEnclaveHeader {
    pub const MAGIC: u32 = 0x524D4255; // "UMBR" in little-endian

    pub unsafe fn from_address(addr: u32) -> Option<Self> {
        let header_ptr = addr as *const UmbraEnclaveHeader;
        let header = core::ptr::read_volatile(header_ptr);

        if header.magic == Self::MAGIC {
            Some(header)
        } else {
            None
        }
    }

    /// Reads `trust_level` (`blob[4]`), which has **two different trust stories
    /// depending on how the blob reached flash** — read this before writing the
    /// first `if header.is_trusted()` in the tree (there is none today).
    ///
    /// - **Signed update path**: trustworthy. Since pkg-tag v2 the package tag
    ///   covers the whole 48-byte UMBR header `blob[0,48)`, this byte included
    ///   (`umbra_update_core::compute_pkg_tag`, `PKG_TAG_LABEL =
    ///   "umbra-update-v2"`), so a post-signing flip dies at the tag gate with
    ///   `TagInvalid` before any flash write.
    /// - **Anything written out of band**: NOT trustworthy. A blob placed in
    ///   flash outside that path is constrained only by the chained measurement,
    ///   and the chain covers `blob[48, 48+288·n)` only — never the header
    ///   metadata. `umbra_chain_core`'s gate accepts any value of this byte
    ///   (`Chain_Residual.verdict_ignores_the_unauthenticated_header_bytes`,
    ///   `Qed`; executable shadow:
    ///   `umbra-chain-core/src/lib_tests.rs::bytes_outside_the_folded_region_are_not_covered`).
    ///
    /// So gating a privilege on this is safe only where the blob's provenance is
    /// the signed update path. Gating one on it unconditionally is a privilege
    /// escalation for any deployment that provisions enclaves by any other means.
    pub fn is_trusted(&self) -> bool {
        self.trust_level == EnclaveTrustLevel::Trusted as u8
    }

    pub fn code_offset(&self) -> u32 {
        UMBRA_HEADER_SIZE
    }

    pub fn efb_count(&self) -> u32 {
        (self.code_size + EFB_SIZE - 1) / EFB_SIZE
    }
}

#[derive(Copy, Clone, PartialEq)]
#[repr(u32)]
pub enum EnclaveState {
    Created = 0,
    Ready = 1,
    Running = 2,
    Suspended = 3,
    Terminated = 4,
    Faulted = 5,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EnclaveContext {
    pub r4: u32,
    pub r5: u32,
    pub r6: u32,
    pub r7: u32,
    pub r8: u32,
    pub r9: u32,
    pub r10: u32,
    pub r11: u32,
    pub psp: u32,
    pub lr: u32,
    pub control: u32,
    pub status: EnclaveState,
    pub result: u32,
}

impl EnclaveContext {
    pub const fn empty() -> Self {
        Self {
            r4: 0,
            r5: 0,
            r6: 0,
            r7: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            psp: 0,
            lr: 0,
            control: 0,
            status: EnclaveState::Created,
            result: 0,
        }
    }
}

// `EnclaveDescriptor` now lives in the verifiable `umbra-ess-core` crate
// (issue #58) — re-exported here so the kernel and the proof share one type and
// every `common::enclave::EnclaveDescriptor` call site is unchanged.
pub use umbra_ess_core::EnclaveDescriptor;
