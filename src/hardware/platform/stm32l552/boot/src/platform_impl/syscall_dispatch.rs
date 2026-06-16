//! SVC + SysTick dispatch surface: SAU/GTZC/MPU bring-up, SHCSR fault
//! enables, and the Non-Secure boot configuration that installs Tock's
//! pre-baked NS-MPU layout.
//!
//! Extracted from `platform_impl.rs`. The NS-MPU layout constant is
//! mirrored by a linker ASSERT in the Tock board crate — see the
//! table comment below.

use arm::mmio::{NVIC_ISER0, NVIC_ISER1, SCB_SHCSR, SYST_CSR};

// ─── Static NS-MPU layout (Tock host port) ──────────────────────────────
// Six regions plus the PPB region (7 total) describing the Non-Secure MPU
// layout Umbra Secure programs once during configure_untrusted_boot(), then leaves
// immutable for the lifetime of the system. Tock runs in NS with a NoopMpu
// stub that never rewrites these registers; the actual memory protection
// lives here.
// Region 3/4 split (kernel-RAM 64K / app-RAM 128K at 0x20010000) is mirrored
// by a linker ASSERT in
// host/stm32l552/tock/boards/nucleo_l552ze_q_umbra/layout.ld — if Tock's
// kernel-RAM footprint grows past 64K, the assert fires AND this constant
// must be rebalanced in lockstep.
// Spec: the design spec

use arm::mpu::{MpuAccessPermission, MpuExecuteNever, NsMpuRegion};

const NS_MPU_LAYOUT_L552: [NsMpuRegion; 7] = [
    // Region 0: Tock kernel flash + vectors — priv-RX
    NsMpuRegion {
        base_addr: 0x0804_0000,
        limit_addr: 0x0806_FFFF,
        ap: MpuAccessPermission::ROPrivilegedOnly,
        xn: MpuExecuteNever::ExecutionPermitted,
        attr_index: 0,
    },
    // Region 1: TBF apps flash — unpriv-RX
    NsMpuRegion {
        base_addr: 0x0807_0000,
        limit_addr: 0x0807_7FFF,
        ap: MpuAccessPermission::ROAny,
        xn: MpuExecuteNever::ExecutionPermitted,
        attr_index: 0,
    },
    // Region 2: Enclave NS flash — unpriv-RX (Tock app reads when calling umbra_create)
    NsMpuRegion {
        base_addr: 0x0807_8000,
        limit_addr: 0x0807_FFFF,
        ap: MpuAccessPermission::ROAny,
        xn: MpuExecuteNever::ExecutionPermitted,
        attr_index: 0,
    },
    // Region 3: Tock kernel RAM — priv-RW, XN
    NsMpuRegion {
        base_addr: 0x2000_0000,
        limit_addr: 0x2000_FFFF,
        ap: MpuAccessPermission::RWPrivilegedOnly,
        xn: MpuExecuteNever::ExecutionNever,
        attr_index: 0,
    },
    // Region 4: App RAM (PSP stacks, grants, heap) — unpriv-RW, XN
    NsMpuRegion {
        base_addr: 0x2001_0000,
        limit_addr: 0x2002_FFFF,
        ap: MpuAccessPermission::RWAny,
        xn: MpuExecuteNever::ExecutionNever,
        attr_index: 0,
    },
    // Region 5: NS peripherals (LPUART1, RCC, GPIO …) — priv-RW, XN, Device
    NsMpuRegion {
        base_addr: 0x4000_0000,
        limit_addr: 0x5FFF_FFFF,
        ap: MpuAccessPermission::RWPrivilegedOnly,
        xn: MpuExecuteNever::ExecutionNever,
        attr_index: 1,
    },
    // Region 6: PPB (SCB, SysTick, NVIC) — priv-RW, XN, Device
    NsMpuRegion {
        base_addr: 0xE000_0000,
        limit_addr: 0xE00F_FFFF,
        ap: MpuAccessPermission::RWPrivilegedOnly,
        xn: MpuExecuteNever::ExecutionNever,
        attr_index: 1,
    },
];

use super::Stm32l5Platform;

impl Stm32l5Platform {
    pub(super) fn init_security_impl(&self) {
        use arm::mpu;
        use arm::sau;
        use drivers::gtzc;
        use kernel::common::memory_layout::{MemoryBlockList, MemoryBlockSecurityAttribute};
        use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;

        //////////////////////////////
        // INITIALIZE MEMORY GUARDS //
        //////////////////////////////

        let mut sau_driver = sau::SauDriver::new();
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] SAU started\n");

        let mut gtzc_driver = gtzc::GtzcDriver::new();
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] GTZC started\n");

        sau_driver.memory_security_guard_init();
        gtzc_driver.memory_security_guard_init();

        // Enable SecureFault (SHCSR.SECUREFAULTENA = bit 19) and MemManage
        // (MEMFAULTENA = bit 16). Without SECUREFAULTENA a secure-state
        // instruction fetch into an MPCBB-NS slot would escalate to HardFault
        // and bypass the Rust `umbra_secure_fault_handler` / ESS-miss recovery
        // path.
        #[cfg(feature = "ess_miss_recovery")]
        {
            let shcsr = SCB_SHCSR;
            unsafe {
                let before = core::ptr::read_volatile(shcsr);
                #[cfg(feature = "boot_tests")]
                {
                    crate::raw_print::print_str("[UMBRASecureBoot] SHCSR before: 0x");
                    crate::raw_print::print_hex(before);
                    crate::raw_print::print_str("\n");
                }
                // 16=MEMFAULTENA, 17=BUSFAULTENA, 18=USGFAULTENA, 19=SECUREFAULTENA.
                // Enabling BUS/USG prevents silent escalation so a misrouted fault
                // surfaces in its own handler instead of the HardFault sink.
                core::ptr::write_volatile(
                    shcsr,
                    before | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19),
                );
                #[cfg(feature = "boot_tests")]
                {
                    let after = core::ptr::read_volatile(shcsr);
                    crate::raw_print::print_str("[UMBRASecureBoot] SHCSR after:  0x");
                    crate::raw_print::print_hex(after);
                    crate::raw_print::print_str("\n");
                }
            }
        }

        // Ensure UsageFault is always enabled (needed for enclave
        // termination detection even without ess_miss_recovery).
        unsafe {
            let shcsr = SCB_SHCSR;
            let val = core::ptr::read_volatile(shcsr);
            if (val & (1 << 18)) == 0 {
                core::ptr::write_volatile(shcsr, val | (1 << 18));
            }
        }

        let mut mpu_driver = mpu::MpuDriver::new();
        unsafe {
            mpu_driver.init();
            // MAIR0 attr 0 = Normal memory, Outer+Inner WB-WA Non-transient (0xFF).
            // RLAR writes that leave AttrIndx=0 (the default in configure_region and
            // in the raw MPU writes in api_impl.rs) pick this attribute. Without this
            // step attr 0 is 0x00 (Device-nGnRnE), and Cortex-M33 treats stack access
            // to Device memory as CONSTRAINED UNPREDICTABLE — the enclave's first
            // `push {r7, lr}` faults with MemManage.DACCVIOL even though the region
            // AP bits permit the write.
            mpu_driver.set_mair(0, 0xFF);
            mpu_driver.enable();
        }
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] MPU started\n");

        // MPU Test: Configure Region 0 for 0x20008000 - 0x2000803F as RW
        let mut region_config = mpu::MpuRegionConfig::new();
        region_config.rnum = 0;
        region_config.base_addr = 0x20008000;
        region_config.limit_addr = 0x2000803F;
        region_config.ap = mpu::MpuAccessPermission::RWPrivilegedOnly;
        region_config.sh = mpu::MpuShareability::NonShareable;
        region_config.xn = mpu::MpuExecuteNever::ExecutionPermitted;
        region_config.enable = true;
        unsafe {
            mpu_driver.configure_region(&region_config);
        }
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str(
            "\t[UMBRASecureBoot] MPU Region 0 Configured: 0x20008000 (RW Priv)\n",
        );

        //////////////////////////////////////////////////
        // CONFIGURE NON-SECURE CODE - FLASH CONTROLLER //
        //////////////////////////////////////////////////

        // The flash controller is initially configured offline at the bank level.
        // Currently, 0x08000000 is designated as watermarked (i.e., secure),
        // while 0x08040000 is non-watermarked, making it non-secure.
        // Pages (2 KB each) within non-watermarked blocks can be selectively modified to be secure.

        /////////////////////////////////////
        // CONFIGURE NON-SECURE CODE - SAU //
        /////////////////////////////////////

        let mut mbl = MemoryBlockList::create_from_range(0x08040000, 0x08080000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
        sau_driver.memory_security_guard_create(&mbl);
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str(
            "\t[UMBRASecureBoot] Untrusted Memory Block Range: 0x08040000 - 0x08080000\n",
        );

        /////////////////////////////////////
        // CONFIGURE NON-SECURE DATA - SAU //
        /////////////////////////////////////

        // Let's use region 1 to split SRAM1
        // 0x20000000 - 0x20020000: Non-Secure (Host)
        // 0x20020000 - 0x20030000: Secure (EFBC)

        // SAU: Mark Host region as Untrusted
        mbl = MemoryBlockList::create_from_range(0x20000000, 0x20020000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
        sau_driver.memory_security_guard_create(&mbl);

        /////////////////////////////////////////////////
        // CONFIGURE NON-SECURE DATA - SRAM CONTROLLER //
        /////////////////////////////////////////////////

        // GTZC: Mark Host region as Untrusted
        mbl = MemoryBlockList::create_from_range(0x20000000, 0x20020000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
        gtzc_driver.memory_security_guard_create(&mbl);

        // GTZC: Mark EFBC region as Trusted
        mbl = MemoryBlockList::create_from_range(0x20020000, 0x20030000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Trusted);
        gtzc_driver.memory_security_guard_create(&mbl);

        // SRAM2 ESS slab — boundaries mirror host/memory.ld.
        mbl = MemoryBlockList::create_from_range(0x20030000, 0x2003E000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Trusted);
        gtzc_driver.memory_security_guard_create(&mbl);
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str(
            "\t[UMBRASecureBoot] Trusted Memory Block Range: 0x20020000 - 0x2003E000\n",
        );

        ///////////////////////////////////
        // CONFIGURE NON-SECURE CALLABLE //
        ///////////////////////////////////

        // Configure the non-secure callable region here
        mbl = MemoryBlockList::create_from_range(0x08030000, 0x0803ffe0);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::TrustedGateway);
        sau_driver.memory_security_guard_create(&mbl);
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str(
            "\t[UMBRASecureBoot] Trusted Gateway Memory Block Range:0x08030000 - 0x0803ffe0\n",
        );

        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] TEST DMA\n");

        // Enable NVIC for DMA1 Channels 1-4 (IRQ 29, 30, 31, 32).
        unsafe {
            let nvic_iser0 = NVIC_ISER0;
            let nvic_iser1 = NVIC_ISER1;
            // IRQ 29, 30, 31 in ISER0
            *nvic_iser0 |= (1 << 29) | (1 << 30) | (1 << 31);
            // IRQ 32 in ISER1 (Bit 0)
            *nvic_iser1 |= 1 << 0;

            cortex_m::interrupt::enable();
        }

        /////////////////////////////////////
        // CONFIGURE NON-SECURE PERIPHERALS - SAU //
        /////////////////////////////////////
        // We must explicitly mark the Non-Secure Peripheral range (0x40000000 - 0x5FFFFFFF) as Non-Secure in SAU.
        // Otherwise, CPU treats accesses as Secure, causing Secure Fault from Non-Secure world.
        // Range: 0x40000000 - 0x4FFFFFFF (Peripherals on AHB/APB)
        mbl = MemoryBlockList::create_from_range(0x40000000, 0x50000000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
        sau_driver.memory_security_guard_create(&mbl);
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str(
            "\t[UMBRASecureBoot] Untrusted Peripheral Range: 0x40000000 - 0x50000000\n",
        );
    }

    pub(super) fn configure_untrusted_boot_impl(&self) {
        // Disable Secure SysTick
        unsafe {
            let syst_csr = SYST_CSR;
            core::ptr::write_volatile(syst_csr, 0x00);
        }
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] SysTick configured (disabled)\n");

        // Point VTOR_NS to SRAM (0x20000000) where the NS host copies its
        // vector table during.data initialization. The IDAU on STM32L5
        // classifies 0x08040000 as Secure for data reads, so the hardware
        // vector fetch fails if VTOR points to flash. SRAM is genuinely NS.
        drivers::rcc::Rcc::set_vtor_ns(0x20000000);

        // Hand Tock a pre-configured Non-Secure MPU.
        // After this call the NS-MPU is locked: nothing in NS rewrites it.
        // (Tock's cortexm33::mpu is replaced with NoopMpu in the board crate.)
        unsafe {
            arm::mpu::program_ns_mpu(&NS_MPU_LAYOUT_L552);
        }
    }
}
