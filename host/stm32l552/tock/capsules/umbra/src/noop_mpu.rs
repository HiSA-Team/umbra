//! Zero-sized stub of `kernel::platform::mpu::MPU`. Umbra Secure programs a
//! static NS-MPU layout during boot (`program_ns_mpu()` in
//! `src/hardware/architecture/arm/src/mpu.rs`); Tock's own MPU layer becomes
//! a no-op as a result. All allocations succeed unmodified.

use kernel::platform::mpu::{self, Permissions, Region};

pub struct NoopMpu;

pub struct NoopMpuConfig;

impl core::fmt::Display for NoopMpuConfig {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

// SAFETY: Process isolation is provided by the static NS-MPU regions
// programmed by Umbra Secure during boot, not by this impl. Tock will still
// invoke these methods on every context switch; they must not panic or block.
unsafe impl mpu::MPU for NoopMpu {
    type MpuConfig = NoopMpuConfig;

    fn enable_app_mpu(&self) {}

    unsafe fn disable_app_mpu(&self) {}

    fn number_total_regions(&self) -> usize {
        0
    }

    fn new_config(&self) -> Option<Self::MpuConfig> {
        Some(NoopMpuConfig)
    }

    fn reset_config(&self, _config: &mut Self::MpuConfig) {}

    fn allocate_region(
        &self,
        unallocated_memory_start: *const u8,
        unallocated_memory_size: usize,
        min_region_size: usize,
        _permissions: Permissions,
        _config: &mut Self::MpuConfig,
    ) -> Option<Region> {
        if min_region_size > unallocated_memory_size {
            return None;
        }
        Some(Region::new(unallocated_memory_start, min_region_size))
    }

    fn remove_memory_region(
        &self,
        _region: Region,
        _config: &mut Self::MpuConfig,
    ) -> Result<(), ()> {
        Ok(())
    }

    fn allocate_app_memory_region(
        &self,
        unallocated_memory_start: *const u8,
        unallocated_memory_size: usize,
        min_memory_size: usize,
        _initial_app_memory_size: usize,
        _initial_kernel_memory_size: usize,
        _permissions: Permissions,
        _config: &mut Self::MpuConfig,
    ) -> Option<(*const u8, usize)> {
        if min_memory_size > unallocated_memory_size {
            return None;
        }
        Some((unallocated_memory_start, min_memory_size))
    }

    fn update_app_memory_region(
        &self,
        _app_memory_break: *const u8,
        _kernel_memory_break: *const u8,
        _permissions: Permissions,
        _config: &mut Self::MpuConfig,
    ) -> Result<(), ()> {
        Ok(())
    }

    unsafe fn configure_mpu(&self, _config: &Self::MpuConfig) {}
}
