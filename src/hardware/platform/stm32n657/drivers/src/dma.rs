//! minimal `umbra_hal::Dma` impl for N657.
//! N657 has no dedicated DMA driver — its production memory transfers
//! either go through XSPI memory-mapped accesses (handled at the OSPI
//! level) or HPDMA invoked by the Cube-AI runtime (out of Umbra's
//! scope). The trait is satisfied by a CPU-memcpy fallback, mirroring
//! the L552-side `CpuDmaCopier` so kernel call sites that bind to
//! `umbra_hal::Dma` work identically across platforms.

/// CPU-memcpy implementation of `umbra_hal::Dma`. Same shape as the
/// L552 `CpuDmaCopier` — same struct name across platforms keeps the
/// platform-agnostic kernel call sites uniform.
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
    AddressOverflow,
}

impl umbra_hal::Dma for CpuDmaCopier {
    type Error = DmaError;

    fn copy(&mut self, src: usize, dst: usize, len: usize) -> Result<(), Self::Error> {
        src.checked_add(len).ok_or(DmaError::AddressOverflow)?;
        dst.checked_add(len).ok_or(DmaError::AddressOverflow)?;
        // SAFETY: addresses are caller-attributed (per trait contract).
        unsafe {
            core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len);
        }
        Ok(())
    }
}
