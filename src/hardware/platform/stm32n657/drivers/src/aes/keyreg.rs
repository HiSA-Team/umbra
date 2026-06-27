//! `AesHardware` — CRYP1-backed AES-128 whose key is delivered over the
//! SAES → CRYP DHUK shared-key bus (issue #45), never loaded from software.
//! `init` configures CRYP for ECB with the shared key (no KEYRx writes);
//! `ctr_xform` switches CRYP to native CTR (both in `aes/ctr.rs`). The AES key
//! never sits in a CPU-visible `AesHardware` field — the cached `key:[u8;16]`
//! was removed (the DoD of #45). The boot-time wrap/share itself is driven by
//! `boot/dhuk_provision.rs`; this constructor only brings up the crypto clocks.

use peripheral_regs::{MmioAccess, RealMmio};

/// Hardware AES via CRYP1, keyed over the SAES shared-key bus. Generic over the
/// MMIO backend (default `RealMmio`) so the `AesEngine` impl in `ctr.rs` can be
/// monomorphised; the firmware path is always `AesHardware<RealMmio>`.
pub struct AesHardware<M: MmioAccess = RealMmio> {
    pub(super) cryp: crate::cryp::Cryp1<M>,
}

impl AesHardware<RealMmio> {
    pub fn new() -> Self {
        use crate::rcc::{self, Rcc};
        let rcc = Rcc::new();
        // Bring up both crypto clocks: CRYP1 for AES, SAES for the boot-time
        // DHUK wrap/share (`dhuk_provision` creates its own `Saes` once clocked).
        rcc.enable_ahb3_clock(rcc::SAESEN);
        rcc.enable_ahb3_clock(rcc::CRYP1EN);
        // SAFETY: the two preceding enable_ahb3 writes are volatile MMIO writes
        // to RCC_AHB3ENR (0x5602_8258). The DSB ensures they are visible to the
        // SAES/CRYP1 peripheral buses before Cryp1::new() accesses its
        // registers. core::arch::asm! is used because cortex_m::asm::dsb() is
        // not available in this no_std driver crate — ARM-only, host-gated.
        #[cfg(target_arch = "arm")]
        unsafe {
            core::arch::asm!("dsb");
        }
        Self {
            cryp: crate::cryp::Cryp1::new(),
        }
    }
}
