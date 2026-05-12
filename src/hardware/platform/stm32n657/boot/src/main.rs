//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>                      //
//                                                                                  //
// Description:                                                                     //
//      This is the main file for Secure Boot, implementing the core function       //
//      secure_boot(). Its primary role is to initialize secure memory regions      //
//      and peripherals, with its implementation tailored to the specific platform. //
//      This version is designed for the STM32N657X0 Cortex-M55. Umbra runs as      //
//      FSBL loaded by Boot ROM from XSPI2 into AXISRAM2; cache invalidation,       //
//      MSP/VTOR relocation, and .data/.bss init happen in startup_n657.s before    //
//      secure_boot() is called.                                                    //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

#![no_main]
#![no_std]
// SAFETY-comment discipline for unsafe blocks. Existing offenders raise warnings
// pending file-by-file scrub; new code is expected to be clean.
#![warn(clippy::undocumented_unsafe_blocks)]

// Umbra Kernel-related crates
use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;

mod crypto_impl;
mod secure_kernel;
mod api_impl;

mod raw_print;
mod handlers;
mod master_key;
mod key_derivation;
mod boot_measurements;
// `validator` module implements per-block HMAC + decrypt validation used at
// runtime by the ESS-miss recovery path. N657 has only chained measurement
// (validation done at boot via the running HMAC chain), so the module is
// compiled only when `ess_miss_recovery` is enabled.
#[cfg(feature = "ess_miss_recovery")]
mod validator;
mod platform_impl;

// Global statics for Kernel dependencies
static mut GLOBAL_CRYPTO: Option<crypto_impl::UmbraCryptoEngine> = None;

static mut GLOBAL_GUARDS: [&'static mut dyn MemorySecurityGuardTrait; 0] = [];




extern "C" {
    static _umb_stack_size: u32;
    static _umb_estack: u32;
    static _umb_fsbl_image_end: u32;
}

#[no_mangle]
pub unsafe fn secure_boot() -> !{
    use crate::platform_impl::Stm32n657Platform;
    use kernel::platform::PlatformBoot;

    let platform = Stm32n657Platform::new();
    platform.init_clocks();
    platform.init_gpio();

    platform.init_uart();
    platform.init_security();

    platform.init_kernel();

    platform.init_external_flash();

    // Measure NPU bytecode + weights flashed at known XSPI2 offsets. Halt
    // boot on mismatch — a tampered model is worse than no boot. Address,
    // length, and expected HMAC come from `boot_measurements.rs`, generated
    // by `tools/measure_blobs.py`. The constants are all-zero for non-NPU
    // hosts, in which case this block is a no-op.
    if crate::boot_measurements::MODEL_BYTECODE_LEN != 0 {
        let kernel = unsafe {
            match crate::secure_kernel::Kernel::get() {
                Some(k) => k,
                None => {
                    crate::raw_print::print_str(
                        "[UMBRASecureBoot] kernel not initialised before boot HMAC\r\n",
                    );
                    loop {}
                }
            }
        };
        let mut hash = drivers::hash::Hash::new();
        match kernel.measure_boot_blobs(&mut hash) {
            Ok(()) => {
                crate::raw_print::print_str(
                    "[UMBRASecureBoot] model+weights HMAC OK\r\n",
                );
            }
            Err(_msg) => {
                crate::raw_print::print_str(
                    "[UMBRASecureBoot] model+weights HMAC FAIL — halt\r\n",
                );
                loop {}
            }
        }
    }

    platform.configure_ns_boot();
    platform.jump_to_ns();

}


#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    /// Trampoline to non-secure world. Assembly lives in asm/arm/trampoline.s.
    pub fn trampoline_to_ns();
}


// DMA IRQ handlers — referenced by the startup_n657.s vector table. No-ops
// on N657 because the boot path does not drive DMA-completion interrupts.
fn handle_dma_irq(_channel: usize) {}

#[no_mangle] pub extern "C" fn DMA1_Channel1_Handler() { handle_dma_irq(0); }
#[no_mangle] pub extern "C" fn DMA1_Channel2_Handler() { handle_dma_irq(1); }
#[no_mangle] pub extern "C" fn DMA1_Channel3_Handler() { handle_dma_irq(2); }
#[no_mangle] pub extern "C" fn DMA1_Channel4_Handler() { handle_dma_irq(3); }
#[no_mangle] pub extern "C" fn DMA1_Channel5_Handler() { handle_dma_irq(4); }
#[no_mangle] pub extern "C" fn DMA1_Channel6_Handler() { handle_dma_irq(5); }
#[no_mangle] pub extern "C" fn DMA1_Channel7_Handler() { handle_dma_irq(6); }
#[no_mangle] pub extern "C" fn DMA1_Channel8_Handler() { handle_dma_irq(7); }
