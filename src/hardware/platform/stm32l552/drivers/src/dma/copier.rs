//! `umbra-hal::Dma` adapter — CPU-memcpy fallback for the L552 driver.
//!
//! Split from `dma.rs` to keep the parent file under the 600-LOC hard-cap.
//!
//! The inherent [`super::Dma`] driver keeps its HW request-queue API
//! (channel reservation, priority, security tagging via secm/dsec/ssec)
//! for the kernel's existing call sites. The trait adapter here is
//! "future-ready" — it lets earlier work expose a platform-agnostic
//! mem-to-mem copy without requiring a kernel-side migration today.

/// Minimal copy engine implementing `umbra_hal::Dma` via
/// `core::ptr::copy_nonoverlapping`. Use for trait-bound generic
/// code; production HW-DMA flows still call [`super::Dma::enqueue`]
/// directly.
pub struct CpuDmaCopier;

impl Default for CpuDmaCopier {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuDmaCopier {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug)]
pub enum DmaError {
    /// `src + len` or `dst + len` overflows.
    AddressOverflow,
}

impl umbra_hal::Dma for CpuDmaCopier {
    type Error = DmaError;

    fn copy(&mut self, src: usize, dst: usize, len: usize) -> Result<(), Self::Error> {
        src.checked_add(len).ok_or(DmaError::AddressOverflow)?;
        dst.checked_add(len).ok_or(DmaError::AddressOverflow)?;
        // SAFETY: addresses are caller-attributed (per trait contract).
        // Both regions are assumed valid for read/write of `len` bytes
        // in the current Secure-side view. Non-overlapping is the
        // common case; if overlap is needed, swap for
        // copy() (overlapping) here.
        unsafe {
            core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len);
        }
        Ok(())
    }
}
