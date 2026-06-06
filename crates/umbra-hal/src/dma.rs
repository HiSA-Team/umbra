//! Dma trait — memory-to-memory copy abstraction.
//! # Scope
//! The minimal abstraction the kernel needs: copy `len` bytes from
//! `src` to `dst`, where the implementation decides whether to use a
//! HW DMA controller or fall back to CPU memcpy. Source and destination
//! addresses are raw `usize` so callers can pass either Secure or NS
//! aliases (the implementation honours whatever the address attribution
//! unit demands).
//! # scope
//! Defines the trait + L552's HW DMA impl. N657 has no separate DMA
//! driver yet (its memory transfers use direct loads via HPDMA from
//! Cube-AI runtime — see `project_n657_hw_findings`). N657's `Dma`
//! impl is a CPU-memcpy fallback that satisfies the trait surface but
//! adds no HW dispatch.
//! # Future direction
//! Channel reservation, priority, double-buffer mode, security
//! (secm/dsec/ssec) — these are platform-specific knobs that stay in
//! the per-platform inherent API. The trait stays narrow because the
//! kernel's actual use is uniform: "copy N bytes between two known-
//! attributed memory regions". Wider surface is follow-up work
//! alongside the DMA→GTZC audit.

/// Memory-to-memory copy trait.
pub trait Dma {
    /// Implementation-specific error.
    type Error: core::fmt::Debug;

    /// Copy `len` bytes from `src` to `dst`. Blocks until complete on
    /// HW-DMA implementations; trivially synchronous on CPU-memcpy
    /// fallback implementations. The implementation is responsible for
    /// honouring the memory attribution unit (GTZC/MPCBB on L552,
    /// RIF/RISAF on N657) — callers do not need to flip security
    /// bits before this call as long as `src` and `dst` are valid
    /// pointers in the address-space view the implementation expects.
    fn copy(&mut self, src: usize, dst: usize, len: usize) -> Result<(), Self::Error>;
}
