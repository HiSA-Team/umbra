//! AEAD trait surface + AES-128-GCM placeholder for `AesHardware`.
//! GCM is not yet wired to CRYP1 (ALGOMODE=0x8 per RM0486 §49.4.13).
//! `seal`/`open` return `NotYetImplemented` until the four-phase GCM
//! state machine (init → header → payload → final) lands.

use super::keyreg::AesHardware;

/// AEAD error codes.
/// `AuthFail` is the security-critical variant: any byte modification to
/// ciphertext/tag/AD/nonce must produce it. Buffer-size mismatches surface
/// separately so callers can distinguish API misuse from tampering.
#[derive(Debug, PartialEq, Eq)]
pub enum AeadError {
    /// `out` slice shorter than `plaintext.len() + Self::TAG_SIZE`.
    OutputTooSmall,
    /// `plaintext_out` slice shorter than `ciphertext.len() - Self::TAG_SIZE`.
    PlaintextBufferTooSmall,
    /// Authentication tag did not match. Plaintext output is undefined and
    /// MUST NOT be released to higher layers.
    AuthFail,
    /// Nonce length does not match `Self::NONCE_SIZE`.
    InvalidNonceLength,
    /// Key length does not match `Self::KEY_SIZE`.
    InvalidKeyLength,
    /// Concrete implementation is declared in the type system but not yet
    /// wired to hardware. Returned by placeholder impls.
    NotYetImplemented,
}

/// Authenticated Encryption with Associated Data.
/// Associated consts (KEY_SIZE / NONCE_SIZE / TAG_SIZE) make this trait
/// **not** object-safe (no `&dyn Aead`). This is deliberate for embedded:
/// callers use it generically, monomorphization keeps the vtable cost at
/// zero. Mirrors the idiom of the upstream `aead` crate.
pub trait Aead {
    /// Symmetric key length in bytes.
    const KEY_SIZE: usize;
    /// Nonce / IV length in bytes. For GCM this is conventionally 12.
    const NONCE_SIZE: usize;
    /// Authentication tag length appended to ciphertext, in bytes.
    const TAG_SIZE: usize;

    /// Encrypt `plaintext` under `key`+`nonce`, authenticate
    /// `plaintext` + `associated_data`. Writes `ciphertext || tag` to
    /// `ciphertext_out` (length must be `plaintext.len() + TAG_SIZE`).
    /// Returns the number of bytes written.
    fn seal(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
    ) -> Result<usize, AeadError>;

    /// Verify tag against `associated_data` and the ciphertext portion of
    /// `ciphertext_and_tag`, then decrypt to `plaintext_out`. The last
    /// `TAG_SIZE` bytes of `ciphertext_and_tag` are the tag. On `Ok`,
    /// returns the plaintext length written. On `AuthFail`, the plaintext
    /// output buffer must be treated as untrusted (typically zeroized).
    fn open(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext_and_tag: &[u8],
        plaintext_out: &mut [u8],
    ) -> Result<usize, AeadError>;
}

// Aead trait surface for AesHardware.
// AES-128-GCM is the target construction: AES-128 in CTR-mode keystream
// XORed with plaintext, GHASH over (associated_data || ciphertext) for the
// 16-byte tag, all under one CRYP ALGOMODE=0x8 configuration. CRYP supports
// GCM natively per RM0486 §49.4.13 (the four-phase init→header→payload→
// final state machine), and the existing `configure_ctr_128_sw_key` is the
// closest neighbor to extend. The placeholder seal/open below returns
// `NotYetImplemented` until the GCM driver lands.
impl Aead for AesHardware {
    const KEY_SIZE: usize = 16; // AES-128
    const NONCE_SIZE: usize = 12; // GCM standard nonce (96-bit; CRYP §49.4.13)
    const TAG_SIZE: usize = 16; // GCM standard tag (128-bit)

    fn seal(
        &mut self,
        _key: &[u8],
        _nonce: &[u8],
        _associated_data: &[u8],
        _plaintext: &[u8],
        _ciphertext_out: &mut [u8],
    ) -> Result<usize, AeadError> {
        // CRYP ALGOMODE=0x8 (GCM) goes here when implemented.
        Err(AeadError::NotYetImplemented)
    }

    fn open(
        &mut self,
        _key: &[u8],
        _nonce: &[u8],
        _associated_data: &[u8],
        _ciphertext_and_tag: &[u8],
        _plaintext_out: &mut [u8],
    ) -> Result<usize, AeadError> {
        Err(AeadError::NotYetImplemented)
    }
}

#[cfg(test)]
mod tests {
    //! Host-side tests for the GCM module.
    //! GCM seal/open are placeholders pending the CRYP ALGOMODE=0x8 wire-up,
    //! so there is no concrete crypto to test here. What is host-testable
    //! today is the `AeadError` surface — derives (PartialEq/Eq/Debug) and
    //! variant distinctness — because those are the API contract every
    //! caller depends on for error-path handling, especially `AuthFail`
    //! (security-critical) versus `OutputTooSmall` (API misuse).
    use super::*;

    /// `AeadError` discriminants must be pairwise distinct. A subtle bug
    /// would be an accidental Clone-derive that conflated variants, or a
    /// future refactor merging `AuthFail` into a generic error — both
    /// would silently weaken the AEAD contract.
    #[test]
    fn aead_error_variants_distinct() {
        assert_ne!(
            AeadError::OutputTooSmall,
            AeadError::PlaintextBufferTooSmall
        );
        assert_ne!(AeadError::OutputTooSmall, AeadError::AuthFail);
        assert_ne!(AeadError::AuthFail, AeadError::InvalidNonceLength);
        assert_ne!(AeadError::AuthFail, AeadError::InvalidKeyLength);
        assert_ne!(AeadError::AuthFail, AeadError::NotYetImplemented);
        assert_ne!(AeadError::InvalidNonceLength, AeadError::InvalidKeyLength);
    }

    /// PartialEq self-reflexivity — guards against a future hand-written
    /// PartialEq impl that breaks the contract.
    #[test]
    fn aead_error_reflexive_eq() {
        assert_eq!(AeadError::AuthFail, AeadError::AuthFail);
        assert_eq!(AeadError::NotYetImplemented, AeadError::NotYetImplemented);
    }

    /// AES-128-GCM canonical sizes (RM0486 §49.4.13, NIST SP 800-38D).
    /// Locked at the trait level — any change here is an API break.
    #[test]
    fn aead_aes128_gcm_sizes() {
        // Aead is generic on AesHardware; we cannot instantiate AesHardware
        // on the host (MMIO). But the associated consts are compile-time
        // values readable through the type alone.
        assert_eq!(<AesHardware as Aead>::KEY_SIZE, 16);
        assert_eq!(<AesHardware as Aead>::NONCE_SIZE, 12);
        assert_eq!(<AesHardware as Aead>::TAG_SIZE, 16);
    }
}
