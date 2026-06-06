//! Hardware AES key-register loading (SW-load path).
//! Holds the `AesHardware` struct plus its constructor. The actual KEYRx
//! ascending-write sequence (K2LR → K2RR → K3LR → K3RR) lives in
//! `cryp.rs::configure_ecb_128_sw_key` and `configure_ctr_128_sw_key`;
//! this module owns the cached-key buffer that those routines consume.
//! Future DHUK-wrap key-isolation path will replace the SW-load here
//! with a SAES → CRYP shared-bus handshake (see module-level docs).

use peripheral_regs::{MmioAccess, RealMmio};

/// Hardware AES via CRYP1.
/// `init` SW-loads the key into CRYP and configures ECB mode (used by
/// `encrypt_block` / `decrypt_block`). `ctr_xform` switches the engine to
/// native CTR mode: CRYP generates the keystream, XORs with input, and
/// increments the counter (IV1RR) internally per block — no manual loop
/// in software. The SAES driver is preserved for a future DHUK-wrapped
/// key-isolation path (`saes.rs`).
/// Generic over the MMIO backend so
/// host tests can inject `MmioHandle`. Default `M = RealMmio` keeps
/// every existing `AesHardware::new()` call site unchanged at the source
/// level — the firmware build monomorphises to `AesHardware<RealMmio>`.
pub struct AesHardware<M: MmioAccess = RealMmio> {
    #[allow(dead_code)] // clocked + ready for DHUK-wrap key isolation path
    pub(super) saes: crate::saes::Saes<M>,
    pub(super) cryp: crate::cryp::Cryp1<M>,
    // Cached most-recent key — `init()` writes it into CRYP_K* (ECB
    // config) so that `encrypt_block`/`decrypt_block` work for
    // `boot_tests` math sanity. `ctr_xform()` re-uses this byte buffer
    // when reconfiguring CRYP from ECB → CTR for a streaming decrypt;
    // CRYP key registers are reloaded as part of `configure_ctr_128_sw_key`
    // (the ascending K2LR→K3RR sequence must be repeated to land KEYVALID).
    pub(super) key: [u8; 16],
}

impl AesHardware<RealMmio> {
    pub fn new() -> Self {
        use crate::rcc::{self, Rcc};
        let rcc = Rcc::new();
        rcc.enable_ahb3_clock(rcc::SAESEN);
        rcc.enable_ahb3_clock(rcc::CRYP1EN);
        // SAFETY: The two preceding enable_ahb3 writes are volatile MMIO writes
        // to RCC_AHB3ENR (0x56028258). The DSB ensures those writes are visible
        // to the SAES and CRYP1 peripheral buses before the Saes::new() and
        // Cryp1::new() constructors below access their registers.
        // core::arch::asm! is used because cortex_m::asm::dsb() is not
        // available in this no_std driver crate. ARM-only intrinsic — gated
        // for host-test builds.
        #[cfg(target_arch = "arm")]
        unsafe {
            core::arch::asm!("dsb");
        }
        Self {
            saes: crate::saes::Saes::new(),
            cryp: crate::cryp::Cryp1::new(),
            key: [0u8; 16],
        }
    }
}

impl<M: MmioAccess> AesHardware<M> {
    /// Test constructor — composes pre-built Saes + Cryp1 with in-memory backends.
    /// Skips the RCC clock-enable that the firmware constructor performs.
    #[allow(dead_code)]
    pub fn new_with_peripherals(saes: crate::saes::Saes<M>, cryp: crate::cryp::Cryp1<M>) -> Self {
        Self {
            saes,
            cryp,
            key: [0u8; 16],
        }
    }
}
