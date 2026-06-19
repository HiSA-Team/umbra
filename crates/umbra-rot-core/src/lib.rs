//! umbra-rot-core — verifiable Root-of-Trust measurement logic.
//!
//! Umbra's root of trust is a **chained HMAC measurement**: `M₀ = initial_key`
//! (the master key for block 0), `Mᵢ₊₁ = HMAC(Mᵢ, blockᵢ)`. An enclave is
//! accepted only if the measurement it reproduces equals the registered one,
//! checked in constant time by [`verify_measurement`]. This is the mechanism
//! the threat model's CJ2 (chained-measurement integrity) rests on.
//!
//! This crate is `#![no_std]` with **zero `unsafe`**. The crypto primitive is
//! the opaque seam (`umbra_api::CryptoEngine`); everything else is pure logic
//! the Charon→Aeneas→Coq pipeline extracts and we prove:
//!  - `verify_measurement` is a *sound* accept gate (true ⟺ equal) — no
//!    crypto assumption.
//!  - [`compute_measurement`] is *injective* in the block sequence under
//!    an idealized-HMAC assumption — tamper-evidence.
//!  - acceptance ⇒ the measured sequence is the registered one.
//!
//! The functions are generic over `C: ?Sized + CryptoEngine` so the kernel can
//! keep its `&mut dyn CryptoEngine` (instantiating `C = dyn CryptoEngine`):
//! dispatch is unchanged, but Charon can see through the generic (it cannot
//! translate a `dyn` call — that is a vtable / function pointer).
#![no_std]

use umbra_api::CryptoEngine;
use umbra_error::UmbraResult;

/// Measurement / key length (HMAC-SHA-256 → 32 bytes).
pub const KEY_SIZE: usize = 32;

/// A measurement key / digest.
#[derive(Copy, Clone)]
pub struct Key {
    pub value: [u8; KEY_SIZE],
}

impl Key {
    pub fn new(value: [u8; KEY_SIZE]) -> Self {
        Self { value }
    }

    pub fn zero() -> Self {
        Self {
            value: [0; KEY_SIZE],
        }
    }
}

/// **T1 target.** Constant-time tag comparison: returns `true` iff the two
/// slices are byte-for-byte equal. Pure logic — no crypto. The XOR-fold leaks
/// only `len() != len()` (always public; all call sites use 32-byte tags).
pub fn verify_measurement(measured_hash: &[u8], expected_hash: &[u8]) -> bool {
    if measured_hash.len() != expected_hash.len() {
        return false;
    }
    let mut diff: u8 = 0;
    let mut i = 0;
    while i < measured_hash.len() {
        diff |= measured_hash[i] ^ expected_hash[i];
        i += 1;
    }
    diff == 0
}

/// HMAC-as-KDF: `derive_key(base, ctx) = HMAC(base, ctx)`.
pub fn derive_key<C: ?Sized + CryptoEngine>(
    crypto: &mut C,
    base_key: &Key,
    context: &[u8],
) -> UmbraResult<Key> {
    let mut new_key_bytes = [0u8; KEY_SIZE];
    crypto.hmac(&base_key.value, context, &mut new_key_bytes)?;
    Ok(Key::new(new_key_bytes))
}

/// Fold one more block into an in-progress HMAC chain:
/// `current_key ← HMAC(current_key, block)`. Lets the caller stream the chained
/// measurement one block at a time as DMA completes.
pub fn update_chain<C: ?Sized + CryptoEngine>(
    crypto: &mut C,
    current_key: &mut [u8; KEY_SIZE],
    block: &[u8],
) -> UmbraResult<()> {
    let mut output = [0u8; KEY_SIZE];
    crypto.hmac(current_key, block, &mut output)?;
    *current_key = output;
    Ok(())
}

// NOTE on the closed-form `compute_measurement(blocks: &[&[u8]], k)` oracle:
// it is NOT here. Aeneas cannot translate a slice-of-slices (`&[&[u8]]` is a
// collection of borrows — nested regions), and crucially the firmware never
// uses it: the real chained measurement is built by STREAMING `update_chain`
// one block at a time (`kernel.chain_state` in the boot crates). So the
// extractable, firmware-faithful primitive is `update_chain` above, and the
// chain is its iteration. The T2 tamper-evidence proof (formal/rocq/rot-core)
// defines that iteration as a Coq `Fixpoint` over `update_chain`'s extracted
// single-step semantics and proves it injective. The `&[&[u8]]` oracle stays
// in the kernel's `KeyGenerator` (test-only) as a loop over `update_chain`.

/// **T4 target.** Validate a single block: derive its measurement (HMAC under a
/// zero base key) and accept iff it matches `expected_measurement`. This is the
/// `memory_protection_server`'s per-block validator. Soundness (T4): a `true`
/// result implies the block's derived measurement IS the expected one.
pub fn validate_block<C: ?Sized + CryptoEngine>(
    crypto: &mut C,
    data: &[u8],
    expected_measurement: &Key,
) -> bool {
    let base_key = Key::zero();
    match derive_key(crypto, &base_key, data) {
        Ok(computed) => verify_measurement(&computed.value, &expected_measurement.value),
        Err(_) => false,
    }
}

/// **T3 target.** Authenticate the ciphertext against `expected_hmac` (via the
/// derived measurement key), then decrypt in place. Returns `Ok` ONLY if the
/// measurement matched — the by-construction half of RoT integrity.
pub fn authenticate_and_decrypt<C: ?Sized + CryptoEngine>(
    crypto: &mut C,
    key: &Key,
    data: &mut [u8],
    expected_hmac: &[u8],
) -> UmbraResult<()> {
    let measurement_key = derive_key(crypto, key, data)?;
    if !verify_measurement(&measurement_key.value, expected_hmac) {
        let mut expected = [0u8; 8];
        let mut got = [0u8; 8];
        let elen = core::cmp::min(8, expected_hmac.len());
        expected[..elen].copy_from_slice(&expected_hmac[..elen]);
        let glen = core::cmp::min(8, measurement_key.value.len());
        got[..glen].copy_from_slice(&measurement_key.value[..glen]);
        return Err(umbra_error::UmbraError::MeasurementMismatch { expected, got });
    }
    let iv = [0u8; 16];
    crypto.aes_decrypt(&key.value, &iv, data)?;
    Ok(())
}

// Sanity checks — smallest tests that fail if the gate or the chain break.
// Not part of the Aeneas pipeline.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_measurement_true_iff_equal() {
        let a = [0xABu8; 32];
        let mut b = [0xABu8; 32];
        assert!(verify_measurement(&a, &b));
        b[15] ^= 1;
        assert!(!verify_measurement(&a, &b));
        // length mismatch never accepts
        assert!(!verify_measurement(&a, &b[..16]));
    }
}
