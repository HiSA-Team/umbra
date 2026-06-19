//! Property-based tests for [`KeyGenerator`] — CJ2 chained-measurement
//! invariants.
//!
//! Wired into `key_generator.rs` via
//! `#[cfg(test)] #[path = "key_generator_proptests.rs"] mod proptests;`.
//!
//! ## Why properties here
//!
//! [`KeyGenerator::compute_measurement`] folds a sequence of blocks
//! into an HMAC chain anchored at `initial_key`. The threat model's CJ2
//! invariant requires:
//!
//! 1. **Determinism** — `compute_measurement(blocks, k)` always returns
//!    the same digest for the same inputs.
//! 2. **Tamper sensitivity** — flipping any single byte in any block
//!    must change the digest. (HMAC's avalanche property is a primitive
//!    requirement here; this proptest enforces that `KeyGenerator` does
//!    not accidentally bypass or short-circuit a block.)
//! 3. **Chain consistency** — the closed-form `compute_measurement` of
//!    `N` blocks must equal the running [`update_chain`] of the same
//!    blocks. A divergence would signal that the streaming and bulk
//!    paths can be desynchronised by an attacker who controls block
//!    arrival timing.
//! 4. **Derive-key purity** — `derive_key(base_key, context)` is a pure
//!    function: the same inputs always produce the same `Key`.
//!
//! ## The mock `CryptoEngine`
//!
//! The proptest path needs a `CryptoEngine` impl that fills the
//! output buffer deterministically and exhibits avalanche under input
//! perturbation. [`MixingMock`] is a 64-bit byte-mixing function over
//! `key || data`. It is **not** cryptographically secure — it does not
//! resist length-extension, second-preimage, or collision attacks. Its
//! sole responsibility is to give `KeyGenerator`'s host-side proptests a
//! deterministic, avalanche-like surface to exercise call semantics
//! against. The real HMAC primitive lives on the firmware path through
//! `CryptoEngine` impls in the PAL crates and is covered by the HW
//! smoke tests.

extern crate std;
use std::vec::Vec;

use super::*;
use proptest::prelude::*;
use umbra_error::UmbraError;

/// A `CryptoEngine` stub that produces deterministic, avalanche-like
/// output for property tests. See module-level doc comment for the
/// security caveat.
struct MixingMock;

impl CryptoEngine for MixingMock {
    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) -> UmbraResult<()> {
        // Byte-mixing FSM: walk key then data through a 64-bit state
        // with multiplicative-then-additive folding, then spread the
        // state across `out` with per-byte rotation.
        let mut state: u64 = 0xa5_a5_a5_a5_a5_a5_a5_a5;
        for &b in key {
            state = state.wrapping_mul(31).wrapping_add(b as u64);
        }
        // Length separator so HMAC(k, ab) != HMAC(ka, b).
        state = state
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(key.len() as u64);
        for &b in data {
            state = state.wrapping_mul(37).wrapping_add(b as u64);
        }
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = ((state >> ((i * 8) % 64)) & 0xff) as u8;
            state = state.rotate_left(7).wrapping_add(i as u64);
        }
        Ok(())
    }

    fn hash(&mut self, data: &[u8], out: &mut [u8]) -> UmbraResult<()> {
        self.hmac(&[], data, out)
    }

    fn aes_decrypt(&mut self, _key: &[u8], _iv: &[u8], _data: &mut [u8]) -> UmbraResult<()> {
        Ok(())
    }
}

fn key_from_bytes(bytes: &[u8]) -> Key {
    let mut value = [0u8; KEY_SIZE];
    let n = core::cmp::min(bytes.len(), KEY_SIZE);
    value[..n].copy_from_slice(&bytes[..n]);
    Key::new(value)
}

proptest! {
    /// `derive_key(base_key, context)` is a pure function of its
    /// inputs: two calls with the same `(base_key, context)` produce
    /// identical `Key` values.
    #[test]
    fn derive_key_is_deterministic(
        base_bytes in prop::array::uniform32(any::<u8>()),
        context in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut crypto = MixingMock;
        let mut gen = KeyGenerator::new(&mut crypto);
        let base = Key::new(base_bytes);
        let k1 = gen.derive_key(&base, &context).expect("derive_key must succeed");

        let mut crypto2 = MixingMock;
        let mut gen2 = KeyGenerator::new(&mut crypto2);
        let k2 = gen2.derive_key(&base, &context).expect("derive_key must succeed");

        prop_assert_eq!(k1.value, k2.value);
    }

    /// `compute_measurement(blocks, initial_key)` is a pure function:
    /// repeated invocations with the same inputs yield the same digest.
    /// Anchors the "stable measurement" invariant the host depends on
    /// for repeatable boot decisions.
    #[test]
    fn compute_measurement_is_deterministic(
        initial_bytes in prop::array::uniform32(any::<u8>()),
        block_count in 1usize..=8,
        block_size in 1usize..=64,
    ) {
        // Build identical block content for both runs.
        let blocks_owned: Vec<Vec<u8>> = (0..block_count)
            .map(|i| (0..block_size).map(|j| ((i * 7 + j) & 0xff) as u8).collect())
            .collect();
        let block_refs: Vec<&[u8]> = blocks_owned.iter().map(|b| b.as_slice()).collect();

        let initial_key = Key::new(initial_bytes);

        let mut crypto = MixingMock;
        let mut gen = KeyGenerator::new(&mut crypto);
        let m1 = gen.compute_measurement(&block_refs, &initial_key)
            .expect("compute_measurement must succeed");

        let mut crypto2 = MixingMock;
        let mut gen2 = KeyGenerator::new(&mut crypto2);
        let m2 = gen2.compute_measurement(&block_refs, &initial_key)
            .expect("compute_measurement must succeed");

        prop_assert_eq!(m1, m2);
    }

    /// Tamper sensitivity: flipping any single byte in any block of an
    /// otherwise-identical input produces a different digest. Catches a
    /// regression where `compute_measurement` short-circuits or omits a
    /// block under specific input shapes.
    #[test]
    fn compute_measurement_detects_block_tamper(
        initial_bytes in prop::array::uniform32(any::<u8>()),
        block_count in 1usize..=4,
        block_size in 1usize..=32,
        tamper_block_idx in 0usize..4,
        tamper_byte_idx in 0usize..32,
        tamper_xor in 1u8..=255,    // exclude 0 to guarantee a real flip
    ) {
        // Build pristine blocks.
        let mut blocks_owned: Vec<Vec<u8>> = (0..block_count)
            .map(|i| (0..block_size).map(|j| ((i * 11 + j) & 0xff) as u8).collect())
            .collect();
        let initial_key = Key::new(initial_bytes);

        let block_refs: Vec<&[u8]> = blocks_owned.iter().map(|b| b.as_slice()).collect();
        let mut crypto = MixingMock;
        let mut gen = KeyGenerator::new(&mut crypto);
        let m_clean = gen.compute_measurement(&block_refs, &initial_key)
            .expect("clean compute_measurement must succeed");
        drop(block_refs);

        // Tamper one byte. Skip the test when indices fall outside the
        // generated blocks (proptest's free generators may overshoot).
        let blk = tamper_block_idx % block_count;
        if tamper_byte_idx >= blocks_owned[blk].len() {
            return Ok(());
        }
        blocks_owned[blk][tamper_byte_idx] ^= tamper_xor;

        let tampered_refs: Vec<&[u8]> = blocks_owned.iter().map(|b| b.as_slice()).collect();
        let mut crypto2 = MixingMock;
        let mut gen2 = KeyGenerator::new(&mut crypto2);
        let m_tampered = gen2.compute_measurement(&tampered_refs, &initial_key)
            .expect("tampered compute_measurement must succeed");

        prop_assert_ne!(
            m_clean,
            m_tampered,
            "tampering block {} byte {} (xor {}) did not change the digest",
            blk,
            tamper_byte_idx,
            tamper_xor,
        );
    }

    /// Chain consistency between streaming (`update_chain`) and bulk
    /// (`compute_measurement`) paths: folding N blocks one-at-a-time
    /// through `update_chain` produces the same final state as
    /// `compute_measurement(blocks)`. Catches a streaming/bulk drift
    /// that an attacker who controls block arrival timing could exploit
    /// to produce a measurement mismatch on a legitimate enclave.
    #[test]
    fn update_chain_streaming_matches_compute_measurement(
        initial_bytes in prop::array::uniform32(any::<u8>()),
        block_count in 1usize..=4,
        block_size in 1usize..=32,
    ) {
        let blocks_owned: Vec<Vec<u8>> = (0..block_count)
            .map(|i| (0..block_size).map(|j| ((i * 13 + j) & 0xff) as u8).collect())
            .collect();
        let block_refs: Vec<&[u8]> = blocks_owned.iter().map(|b| b.as_slice()).collect();

        let initial_key = Key::new(initial_bytes);

        // Streaming path: walk update_chain over each block.
        let mut crypto = MixingMock;
        let mut gen = KeyGenerator::new(&mut crypto);
        let mut streaming = initial_key.value;
        for block in &block_refs {
            gen.update_chain(&mut streaming, block).expect("update_chain must succeed");
        }

        // Bulk path: compute_measurement over the same sequence.
        let mut crypto2 = MixingMock;
        let mut gen2 = KeyGenerator::new(&mut crypto2);
        let bulk = gen2.compute_measurement(&block_refs, &initial_key)
            .expect("compute_measurement must succeed");

        prop_assert_eq!(streaming, bulk);
    }

    /// `authenticate_and_decrypt` returns `Ok` when `expected_hmac`
    /// matches the measurement key derived from `(key, data)`. This is
    /// the legitimate-enclave path: the caller supplies a fresh
    /// ciphertext and the HMAC pre-computed at enclave-create time,
    /// and gets the in-place decryption (a no-op under [`MixingMock`]).
    #[test]
    fn authenticate_and_decrypt_happy_path_returns_ok(
        key_bytes in prop::array::uniform32(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        // Precompute the measurement that `derive_key(key, data)` will
        // yield under MixingMock, and feed it back as expected_hmac.
        let mut expected = [0u8; KEY_SIZE];
        let mut precompute = MixingMock;
        precompute.hmac(&key_bytes, &data, &mut expected)
            .expect("hmac mock cannot fail");

        let key = Key::new(key_bytes);
        let mut auth_mock = MixingMock;
        let mut gen = KeyGenerator::new(&mut auth_mock);
        let mut data_mut = data.clone();
        let result = gen.authenticate_and_decrypt(&key, &mut data_mut, &expected);

        prop_assert!(result.is_ok(), "happy path must succeed: {:?}", result);
    }

    /// `authenticate_and_decrypt` returns `Err(MeasurementMismatch)`
    /// when `expected_hmac` disagrees with the derived measurement key.
    /// The error variant carries the first 8 bytes of both sides for
    /// off-chip diagnostic triage; this proptest verifies both the
    /// variant identity and the byte-slice content.
    #[test]
    fn authenticate_and_decrypt_tamper_returns_measurement_mismatch(
        key_bytes in prop::array::uniform32(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 1..64),
        tamper_idx in 0usize..KEY_SIZE,
        tamper_xor in 1u8..=255,
    ) {
        // Precompute the legitimate measurement, then tamper one byte.
        let mut expected = [0u8; KEY_SIZE];
        let mut precompute = MixingMock;
        precompute.hmac(&key_bytes, &data, &mut expected)
            .expect("hmac mock cannot fail");
        expected[tamper_idx] ^= tamper_xor;

        // Capture what the actual measurement will be inside
        // authenticate_and_decrypt so we can assert the `got` field.
        let mut actual = [0u8; KEY_SIZE];
        let mut shadow = MixingMock;
        shadow.hmac(&key_bytes, &data, &mut actual)
            .expect("hmac mock cannot fail");

        let key = Key::new(key_bytes);
        let mut auth_mock = MixingMock;
        let mut gen = KeyGenerator::new(&mut auth_mock);
        let mut data_mut = data.clone();
        let result = gen.authenticate_and_decrypt(&key, &mut data_mut, &expected);

        match result {
            Err(UmbraError::MeasurementMismatch { expected: e, got: g }) => {
                let mut want_expected = [0u8; 8];
                want_expected.copy_from_slice(&expected[..8]);
                let mut want_got = [0u8; 8];
                want_got.copy_from_slice(&actual[..8]);
                prop_assert_eq!(e, want_expected, "expected[..8] mismatch");
                prop_assert_eq!(g, want_got, "got[..8] mismatch");
            }
            other => prop_assert!(
                false,
                "expected MeasurementMismatch, got {:?}",
                other,
            ),
        }
    }

    /// `authenticate_and_decrypt` must safely handle an
    /// `expected_hmac` shorter than 8 bytes: the diagnostic `expected`
    /// array is built via `copy_from_slice(&expected_hmac[..min(8,
    /// len)])`, so a short slice must NOT cause an over-read. The
    /// trailing bytes of the diagnostic array stay at their default
    /// `0` value.
    #[test]
    fn authenticate_and_decrypt_short_expected_hmac_truncates_safely(
        key_bytes in prop::array::uniform32(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 1..32),
        expected_len in 0usize..8,
    ) {
        // Pattern byte 0xA5 so the truncation is observable.
        let supplied: Vec<u8> = (0..expected_len).map(|_| 0xA5).collect();

        let key = Key::new(key_bytes);
        let mut auth_mock = MixingMock;
        let mut gen = KeyGenerator::new(&mut auth_mock);
        let mut data_mut = data.clone();
        let result = gen.authenticate_and_decrypt(&key, &mut data_mut, &supplied);

        match result {
            Err(UmbraError::MeasurementMismatch { expected: e, got: _ }) => {
                for i in 0..expected_len {
                    prop_assert_eq!(
                        e[i],
                        0xA5,
                        "expected[{}] must copy from the supplied slice",
                        i,
                    );
                }
                for i in expected_len..8 {
                    prop_assert_eq!(
                        e[i],
                        0,
                        "expected[{}] beyond the supplied len must stay at default 0",
                        i,
                    );
                }
            }
            other => prop_assert!(
                false,
                "expected MeasurementMismatch, got {:?}",
                other,
            ),
        }
    }
}
