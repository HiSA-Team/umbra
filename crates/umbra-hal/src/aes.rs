//! Aes trait — symmetric block cipher with ECB/CTR modes.
//! # Design
//! Three-method API: `configure(key, mode)` then `set_iv(&iv)` (CTR only)
//! then `process(input, output)`. The split between configure + process
//! lets callers reuse the same keyed engine across multiple blocks
//! without re-loading the key on every call — material for the L552
//! AesEmulated path (T-table expansion is the expensive step) and for
//! the N657 HW CRYP1 path (KEYRx writes have a documented ordering
//! requirement, see project_n657_aes_hw memory).
//! # Modes supported ()
//! - `EcbEncrypt` — raw block encrypt, len must be multiple of 16
//! - `EcbDecrypt` — raw block decrypt, len must be multiple of 16
//! - `CtrEncrypt` — counter mode, any length, decrypt = encrypt (XOR-symmetric)
//!
//! GCM / CCM / CMAC are + work (DMA→GTZC audit may
//! surface AEAD requirements first).
//! # Error type
//! Associated to the trait so platform impls can carry HW-specific error
//! info (CRYP1 BUSY-timeout, KEYR write race, OTFDEC key-region clash).
//! Migration to a unified `UmbraError` lands when umbra-error reaches
//! the kernel boundary (/).

/// AES key sizes Umbra supports. AES-128 covers production paths
/// (master-key derived 16-byte subkeys); AES-256 reserved for direct
/// master-key use in future audit work.
#[derive(Debug, Clone, Copy)]
pub enum AesKey<'a> {
    Bits128(&'a [u8; 16]),
    Bits256(&'a [u8; 32]),
}

/// AES cipher mode. CTR is its own decrypt (XOR-symmetric) — both
/// directions use `CtrEncrypt`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AesMode {
    EcbEncrypt,
    EcbDecrypt,
    CtrEncrypt,
}

/// Symmetric block cipher trait.
pub trait Aes {
    /// Implementation-specific error.
    type Error: core::fmt::Debug;

    /// Load a key and lock the mode. Subsequent `process` calls operate
    /// with this config until `configure` is called again.
    fn configure(&mut self, key: AesKey<'_>, mode: AesMode) -> Result<(), Self::Error>;

    /// Set the IV / counter block. Required before any CTR `process`
    /// call. ECB modes ignore the IV and may skip this.
    fn set_iv(&mut self, iv: &[u8; 16]) -> Result<(), Self::Error>;

    /// Process `input` → `output`. For ECB, `input.len()` must be a
    /// multiple of 16 and `output.len() >= input.len()`. For CTR, any
    /// length; output XORs the keystream against input byte-for-byte.
    fn process(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Self::Error>;
}
