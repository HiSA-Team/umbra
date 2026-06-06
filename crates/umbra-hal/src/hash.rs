//! Hash trait — cryptographic hash function with chained-measurement use case.
//! # Design
//! Three-phase: `init()` → `update(*)` → `finalize(&mut [u8; 32])`. The
//! 32-byte output size is hard-coded to SHA-256 / SHA3-256; if future
//! Umbra targets need other hash sizes, generalise via associated
//! `const DIGEST_LEN: usize`.
//! # Error type
//! Associated to the trait so platform impls can carry HW-specific error
//! info (e.g. the L552 HASH peripheral `CR.STARTERR` bit, or N657's
//! RIFSC-denial when the HW HASH block isn't reachable). Will migrate to
//! a top-level `UmbraError` via `From` impls when umbra-error lands
//! (/).

/// Cryptographic hash function trait. Implementations must produce a
/// 32-byte digest (SHA-256 or SHA3-256 byte-for-byte) so the chained-
/// measurement output is identical across L552 HW HASH, N657 SW SHA-256,
/// and host-side `TestHash`.
pub trait Hash {
    /// Implementation-specific error.
    type Error: core::fmt::Debug;

    /// Reset the hash state to the empty digest.
    fn init(&mut self) -> Result<(), Self::Error>;

    /// Feed bytes into the hash. May be called multiple times.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Finalize and copy the 32-byte digest into `output`. After
    /// finalizing, the next `update` returns an error unless `init` is
    /// called first.
    fn finalize(&mut self, output: &mut [u8; 32]) -> Result<(), Self::Error>;
}
