//! Remote-attestation quote: a fixed-layout, HMAC-tagged report of the device's
//! enclave measurement, authenticated version, anti-rollback floor, state-continuity
//! generation, and platform health. Pure logic — the HMAC primitive is injected
//! (HW HASH on target, mock in tests), mirroring `state_root::compute_root`.
//!
//! Byte layout (little-endian, packed). Offsets are NORMATIVE — the verifier CLI
//! (`tools/attest_update.py`) parses the same layout; keep both in lock-step.
//!
//! ```text
//!  off  size  field
//!    0     4   magic  = QUOTE_MAGIC ("UQT1")
//!    4    16   nonce
//!   20     4   enclave_id
//!   24     1   status
//!   25    32   bm            (chain_state / block measurement)
//!   57     4   author_id
//!   61     4   version       (authenticated; 0 if version_bind OFF)
//!   65     4   floor         (TAMP anti-rollback floor for author_id)
//!   69     4   anchor_gen    (state-continuity generation; 0 = cold/absent)
//!   73     1   restore       (0 None 1 Resume 2 ColdGenesis 3 Reject)
//!   74     4   reset_cause   (RCC_RSR snapshot at boot)
//!   78     1   hdpl
//!   79     4   flags         (bit0 version_bind, bit1.. reserved alg)
//!   83    32   tag = HMAC(K_attest, bytes[0..83])
//!  115         QUOTE_LEN
//! ```

pub const QUOTE_MAGIC: u32 = 0x3154_5155; // "UQT1" little-endian bytes 55 51 54 31
pub const QUOTE_PREIMAGE_LEN: usize = 83;
pub const QUOTE_LEN: usize = QUOTE_PREIMAGE_LEN + 32;

/// The variable runtime state that goes into a quote. The caller (boot glue)
/// fills this from the live `Kernel` + TAMP + RCC before signing.
#[derive(Clone, Copy)]
pub struct QuoteFields {
    pub nonce: [u8; 16],
    pub enclave_id: u32,
    pub status: u8,
    pub bm: [u8; 32],
    pub author_id: u32,
    pub version: u32,
    pub floor: u32,
    pub anchor_gen: u32,
    pub restore: u8,
    pub reset_cause: u32,
    pub hdpl: u8,
    pub flags: u32,
}

impl QuoteFields {
    /// Serialize the signed prefix (everything except the trailing tag) into `buf`.
    /// Returns the number of bytes written (== `QUOTE_PREIMAGE_LEN`).
    pub fn write_preimage(&self, buf: &mut [u8; QUOTE_PREIMAGE_LEN]) -> usize {
        buf[0..4].copy_from_slice(&QUOTE_MAGIC.to_le_bytes());
        buf[4..20].copy_from_slice(&self.nonce);
        buf[20..24].copy_from_slice(&self.enclave_id.to_le_bytes());
        buf[24] = self.status;
        buf[25..57].copy_from_slice(&self.bm);
        buf[57..61].copy_from_slice(&self.author_id.to_le_bytes());
        buf[61..65].copy_from_slice(&self.version.to_le_bytes());
        buf[65..69].copy_from_slice(&self.floor.to_le_bytes());
        buf[69..73].copy_from_slice(&self.anchor_gen.to_le_bytes());
        buf[73] = self.restore;
        buf[74..78].copy_from_slice(&self.reset_cause.to_le_bytes());
        buf[78] = self.hdpl;
        buf[79..83].copy_from_slice(&self.flags.to_le_bytes());
        QUOTE_PREIMAGE_LEN
    }
}

/// Build a signed quote into `out`. `hmac(key, &[preimage]) -> [u8;32]` is the
/// injected primitive. The fixed single-part slice keeps the HW HMAC buffer at
/// exactly `QUOTE_PREIMAGE_LEN`.
pub fn build_quote(
    q: &QuoteFields,
    key: &[u8],
    hmac: impl FnOnce(&[u8], &[&[u8]]) -> [u8; 32],
    out: &mut [u8; QUOTE_LEN],
) {
    let mut pre = [0u8; QUOTE_PREIMAGE_LEN];
    q.write_preimage(&mut pre);
    out[..QUOTE_PREIMAGE_LEN].copy_from_slice(&pre);
    let tag = hmac(key, &[&pre]);
    out[QUOTE_PREIMAGE_LEN..].copy_from_slice(&tag);
}

#[cfg(test)]
#[path = "attestation_tests.rs"]
mod tests;
