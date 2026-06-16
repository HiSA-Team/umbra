//! Software crypto for the QEMU RISC-V target — the `CryptoEngine` the monitor
//! hands the kernel, exactly as the STM32 platforms do.
//!
//! Like L552/N657, the per-platform `UmbraCryptoEngine` implements
//! [`kernel::key_storage_server::crypto::CryptoEngine`] (`hmac` / `hash` /
//! `aes_decrypt`); the `secure_kernel` measures + decrypts enclaves through that
//! trait object rather than calling crypto free functions. The difference from
//! the ARM platforms is only the backend: QEMU `virt` has no HASH/CRYP
//! peripheral, so SHA-256 is software (this file) and AES-128-CTR comes from the
//! host-testable `umbra-riscv-arch` core. The `hash()` path still dispatches
//! through the [`umbra_hal::Hash`] trait, identical to L552's HW HASH path.
//!
//! `UmbraCryptoEngine` is a zero-sized stateless value (no HW handle to own), so
//! — unlike L552/N657, which store the engine in their MonitorState — it is
//! constructed where used in the lifecycle.

use kernel::key_storage_server::crypto::CryptoEngine;
use umbra_error::{UmbraError, UmbraResult};
use umbra_hal::Hash as HashTrait;
use umbra_riscv_arch::aes_kat::ctr_xcrypt;

/// Per-image master key seeding the enclave measurement chain.
pub use crate::master_key::MASTER_KEY;

/// KDF label for the enclave encryption subkey. MUST stay byte-for-byte in sync
/// with `key_derivation::ENC_KEY_LABEL` (L552) and `sign_enclave.py`.
pub const ENC_KEY_LABEL: &[u8] = b"umbra-enc-v1";

/// KDF label for the per-block HMAC subkey (runtime ESS-miss re-validation).
/// MUST match `key_derivation::HMAC_KEY_LABEL` (L552) and `protect_enclave.py`.
pub const HMAC_KEY_LABEL: &[u8] = b"umbra-hmac-v1";

/// Placeholder init to match the STM32 boot sequence (`init_kernel` calls it).
/// The software engine has no peripheral to bring up.
pub fn init() {}

// ── Software SHA-256 ─────────────────────────────────────────────────────────

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming SHA-256 state. Exposed to the engine via the [`umbra_hal::Hash`]
/// trait (so the `hash()` path is HAL-dispatched like L552); HMAC uses the
/// inherent methods directly since the trait does not model keyed hashing.
struct Sha256 {
    h: [u32; 8],
    block: [u8; 64],
    fill: usize,
    total: u64,
}

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            fill: 0,
            total: 0,
        }
    }

    fn compress(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                self.block[i * 4],
                self.block[i * 4 + 1],
                self.block[i * 4 + 2],
                self.block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = self.h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            self.h[i] = self.h[i].wrapping_add(v[i]);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        while !data.is_empty() {
            let n = core::cmp::min(64 - self.fill, data.len());
            self.block[self.fill..self.fill + n].copy_from_slice(&data[..n]);
            self.fill += n;
            data = &data[n..];
            if self.fill == 64 {
                self.compress();
                self.fill = 0;
            }
        }
    }

    /// Pad and produce the digest. Takes `&mut self` (it mutates while padding);
    /// the state must not be reused afterwards without re-`new`/`init`.
    fn finish(&mut self) -> [u8; 32] {
        let bitlen = self.total * 8;
        self.update(&[0x80]);
        while self.fill != 56 {
            self.update(&[0x00]);
        }
        self.update(&bitlen.to_be_bytes());
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

impl HashTrait for Sha256 {
    type Error = core::convert::Infallible;

    fn init(&mut self) -> Result<(), Self::Error> {
        *self = Sha256::new();
        Ok(())
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Sha256::update(self, input);
        Ok(())
    }

    fn finalize(&mut self, output: &mut [u8; 32]) -> Result<(), Self::Error> {
        *output = self.finish();
        Ok(())
    }
}

/// Raw SHA-256 (used only to shorten an over-long HMAC key, per RFC 2104).
fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finish()
}

/// HMAC-SHA256 of `data` under `key` (RFC 2104). Internal helper for the
/// engine's `hmac()` — the `umbra_hal::Hash` trait does not model keyed hashing.
fn hmac_raw(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k0 = [0u8; 64];
    if key.len() > 64 {
        k0[..32].copy_from_slice(&sha256_raw(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let ih = inner.finish();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&ih);
    outer.finish()
}

// ── CryptoEngine — the kernel boundary, mirroring L552/N657 ──────────────────

/// The RISC-V monitor's [`CryptoEngine`]: software SHA-256/HMAC + the
/// `umbra-riscv-arch` AES-128-CTR core. Zero-sized and stateless.
pub struct UmbraCryptoEngine;

impl UmbraCryptoEngine {
    pub fn new() -> Self {
        UmbraCryptoEngine
    }
}

impl Default for UmbraCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoEngine for UmbraCryptoEngine {
    fn hmac(&mut self, key: &[u8], data: &[u8], output: &mut [u8]) -> UmbraResult<()> {
        if output.len() < 32 {
            return Err(UmbraError::LengthMismatch);
        }
        output[..32].copy_from_slice(&hmac_raw(key, data));
        Ok(())
    }

    fn hash(&mut self, data: &[u8], output: &mut [u8]) -> UmbraResult<()> {
        if output.len() < 32 {
            return Err(UmbraError::LengthMismatch);
        }
        // Trait-dispatched SHA-256 — same byte-for-byte digest as L552's HW HASH
        // path, flowing through `umbra_hal::Hash`.
        let mut sha = Sha256::new();
        let mut digest = [0u8; 32];
        HashTrait::init(&mut sha).map_err(|_| UmbraError::HashHardware)?;
        HashTrait::update(&mut sha, data).map_err(|_| UmbraError::HashHardware)?;
        HashTrait::finalize(&mut sha, &mut digest).map_err(|_| UmbraError::HashHardware)?;
        output[..32].copy_from_slice(&digest);
        Ok(())
    }

    fn aes_decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> UmbraResult<()> {
        // AES-128-CTR is symmetric: decrypt == encrypt-keystream-XOR. 32-byte
        // HMAC-KDF subkeys are truncated to 16 bytes for AES-128, exactly as the
        // ARM platforms' `aes_decrypt` does.
        if key.len() < 16 || iv.len() < 16 {
            return Err(UmbraError::LengthMismatch);
        }
        let aes_key: [u8; 16] = key[..16]
            .try_into()
            .map_err(|_| UmbraError::LengthMismatch)?;
        let iv16: [u8; 16] = iv[..16]
            .try_into()
            .map_err(|_| UmbraError::LengthMismatch)?;
        ctr_xcrypt(&aes_key, &iv16, data);
        Ok(())
    }
}

// ── Key derivation through the engine (mirrors L552 `key_derivation`) ─────────

/// Derive the AES-128 enclave encryption key:
/// `HMAC-SHA256(MASTER_KEY, "umbra-enc-v1")` (the caller truncates to 16 bytes
/// at `aes_decrypt`). Keeps the measurement key (`MASTER_KEY`) and the
/// encryption key in separate domains, exactly as the L552 ProVerif model
/// requires.
pub fn derive_enc_key(crypto: &mut dyn CryptoEngine) -> UmbraResult<[u8; 32]> {
    let mut out = [0u8; 32];
    crypto
        .hmac(&MASTER_KEY, ENC_KEY_LABEL, &mut out)
        .map_err(|_| UmbraError::KeyDerivation)?;
    Ok(out)
}

/// Derive the per-block HMAC key: `HMAC-SHA256(MASTER_KEY, "umbra-hmac-v1")`.
/// Used by the runtime ESS-miss path to re-validate a single block's `sig`
/// before reinstalling it. Mirrors `key_derivation::derive_hmac_key`.
pub fn derive_hmac_key(crypto: &mut dyn CryptoEngine) -> UmbraResult<[u8; 32]> {
    let mut out = [0u8; 32];
    crypto
        .hmac(&MASTER_KEY, HMAC_KEY_LABEL, &mut out)
        .map_err(|_| UmbraError::KeyDerivation)?;
    Ok(out)
}
