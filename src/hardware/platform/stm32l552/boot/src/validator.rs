//! Rust analog of the ProVerif `Validator` process in
//! `docs/formal/UmbraIntegrityFixValidator.pv`.
//!
//! `validate_block` is the ONLY producer of `ValidatedBlock`. The private
//! `_seal` field prevents any other module from constructing one, so a
//! function that takes `ValidatedBlock` as an argument is provably getting
//! a value that passed the HMAC check inside `validate_block`.
//!
//! `ValidatedBlock.block_id` is set from the `expected_block_id` parameter,
//! which mirrors the formal model's `=b` pattern-match on the Validator
//! response tuple: the block id coming out of the Validator is the one
//! the caller asked for — block confusion is a compile-time impossibility
//! on this boundary.

use kernel::key_storage_server::crypto::CryptoEngine;

pub const CODE_BLOCK_SIZE: usize = 256;
pub const BLOCK_META_SIZE: usize = 32;

pub struct ValidatedBlock {
    pub block_id: u32,
    pub plaintext: [u8; CODE_BLOCK_SIZE],
    pub metadata: [u8; BLOCK_META_SIZE],
    _seal: (),
}

#[derive(Debug, Copy, Clone)]
pub enum ValidationError {
    HmacMismatch,
    DecryptFailed,
    CryptoUnavailable,
}

pub fn validate_block(
    crypto: &mut dyn CryptoEngine,
    expected_block_id: u32,
    ciphertext: &[u8; CODE_BLOCK_SIZE],
    metadata: &[u8; BLOCK_META_SIZE],
    hmac_on_flash: &[u8; 32],
    hmac_key: &[u8; 32],
    enc_key: &[u8; 32],
) -> Result<ValidatedBlock, ValidationError> {
    // 1. Reconstruct HMAC input: [block_id_le || ciphertext || metadata].
    //    Must match `tools/protect_enclave.py`'s `binding_input` byte-for-byte.
    let mut input = [0u8; 4 + CODE_BLOCK_SIZE + BLOCK_META_SIZE];
    input[0..4].copy_from_slice(&expected_block_id.to_le_bytes());
    input[4..4 + CODE_BLOCK_SIZE].copy_from_slice(ciphertext);
    input[4 + CODE_BLOCK_SIZE..].copy_from_slice(metadata);

    // 2. Compute expected HMAC with the secret hmac_key.
    let mut computed = [0u8; 32];
    crypto.hmac(hmac_key, &input, &mut computed)
          .map_err(|_| ValidationError::HmacMismatch)?;

    // 3. Constant-time compare against the on-flash HMAC.
    let mut diff: u8 = 0;
    for i in 0..32 { diff |= computed[i] ^ hmac_on_flash[i]; }
    if diff != 0 { return Err(ValidationError::HmacMismatch); }

    // 4. Install plaintext.
    //    L552: decrypt AES-CTR into a fresh local buffer.
    //    L562: the `ciphertext` slice already holds plaintext. OTFDEC transparently
    //    decrypts, OCTOSPI read, and `protect_enclave.py --hmac-over-plaintext`
    //    binds the on-flash sig to the plaintext bytes, so the HMAC check above
    //    is exactly the integrity guarantee the validator provides. Re-running
    //    AES-decrypt on plaintext would produce garbage (and silently — see the
    //    block-1 post-preempt MemManage investigation on 2026-04-13).
    let mut plaintext = *ciphertext;
    #[cfg(not(feature = "stm32l562"))]
    {
        let iv = [0u8; 16];
        crypto.aes_decrypt(enc_key, &iv, &mut plaintext)
              .map_err(|_| ValidationError::DecryptFailed)?;
    }
    #[cfg(feature = "stm32l562")]
    {
        let _ = (crypto, enc_key);
    }

    // 5. Bind block_id into the return type — the formal-model `=b`.
    Ok(ValidatedBlock {
        block_id: expected_block_id,
        plaintext,
        metadata: *metadata,
        _seal: (),
    })
}
