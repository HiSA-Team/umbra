//! Shared constants for enclave state continuity. The anti-rollback decision now
//! lives in the **root-in-anchor** model (`state_root` + `state_checkpoint`,
//! 2026-07-02 redesign); the old per-sector version reconciliation that lived here
//! was superseded (it compared versions from untrusted flash — see X1/X2 in the
//! ADR). See `book/src/decisions/010-state-continuity-commit-reconciliation.md`.

/// Maximum independently-checkpointed state sectors per enclave.
pub const MAX_STATE_SECTORS: usize = 16;
/// Ciphertext bytes per state sector (= one 4 KB NOR subsector).
pub const STATE_SECTOR_SIZE: usize = 4096;
