
//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>                       //
//         Salvatore Bramante <salvatore.bramante@imtlucca.it>                      //
//                                                                                  //
// Description:                                                                     //
//      This is the main file for Secure Boot, implementing the core function       //
//      secure_boot(). Its primary role is to initialize secure memory regions      //
//      and peripherals, with its implementation tailored to the specific platform. //
//      This version is designed for the STM32L552 microcontroller.                 //
//      Additionally, this project handles the setup of peripheral handlers,        //
//      while base handlers, including the vector table, are defined in the         //
//      architecture-specific crate.                                                //
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
mod validator;
// G3 speculative prefetch — calls Kernel::handle_ess_miss, which is itself
// gated to the `ess_miss_recovery` feature, so the module is only valid
// when that feature is on.
#[cfg(feature = "ess_miss_recovery")]
mod prefetch;
mod platform_impl;

#[cfg(feature = "benchmark")]
mod benchmark;

// Global statics for Kernel dependencies
static mut GLOBAL_CRYPTO: Option<crypto_impl::UmbraCryptoEngine> = None;

static mut GLOBAL_GUARDS: [&'static mut dyn MemorySecurityGuardTrait; 0] = [];

// 16 KB BSS buffer for the OTFDEC ENC-mode cipher pass.
// Placed in BSS (not on the stack) because _SECURE_KERNEL_DATA_MEMORY_ is 56 KB
// and a 16 KB stack buffer would likely overflow the secure-boot stack at reset.
// 64 KB would exceed the 56 KB data region — do not increase past 0x4000.
#[cfg(feature = "stm32l562")]
const OTFDEC_REGION_SIZE_BSS: usize = 0x4000; // 16 KB
#[cfg(feature = "stm32l562")]
static mut PLAINTEXT_BUF: [u8; OTFDEC_REGION_SIZE_BSS] = [0u8; OTFDEC_REGION_SIZE_BSS];
#[cfg(feature = "stm32l562")]
static mut CIPHERTEXT_BUF: [u8; OTFDEC_REGION_SIZE_BSS] = [0u8; OTFDEC_REGION_SIZE_BSS];




extern "C" {
    static _umb_stack_size: u32;
    static _umb_estack: u32;
    static _host_stack_size: u32; // Assuming this is available just like _host_entry_point
}

#[no_mangle]
pub unsafe fn secure_boot() -> !{
    use crate::platform_impl::Stm32l5Platform;
    use kernel::platform::PlatformBoot;

    let platform = Stm32l5Platform::new();
    platform.init_clocks();
    platform.init_gpio();

    platform.init_uart();
    platform.init_security();

    platform.init_kernel();

    platform.init_external_flash();

    platform.configure_ns_boot();
    platform.jump_to_ns();

}


#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    /// Trampoline to non-secure world. Assembly lives in asm/arm/trampoline.s.
    pub fn trampoline_to_ns();
}


// Synchronization for DMA Tests
static mut DMA_COMPLETED: bool = false;

#[no_mangle]
pub extern "Rust" fn is_dma_complete() -> bool {
    unsafe { core::ptr::read_volatile(&raw const DMA_COMPLETED) }
}

#[no_mangle]
pub extern "Rust" fn reset_dma_complete() {
    unsafe { core::ptr::write_volatile(&raw mut DMA_COMPLETED, false); }
}

#[no_mangle]
pub extern "C" fn DMA1_Channel1_Handler() { handle_dma_irq(0); }
#[no_mangle]
pub extern "C" fn DMA1_Channel2_Handler() { handle_dma_irq(1); }
#[no_mangle]
pub extern "C" fn DMA1_Channel3_Handler() { handle_dma_irq(2); }
#[no_mangle]
pub extern "C" fn DMA1_Channel4_Handler() { handle_dma_irq(3); }
#[no_mangle]
pub extern "C" fn DMA1_Channel5_Handler() { handle_dma_irq(4); }
#[no_mangle]
pub extern "C" fn DMA1_Channel6_Handler() { handle_dma_irq(5); }
#[no_mangle]
pub extern "C" fn DMA1_Channel7_Handler() { handle_dma_irq(6); }
#[no_mangle]
pub extern "C" fn DMA1_Channel8_Handler() { handle_dma_irq(7); }

fn handle_dma_irq(ch_idx: u32) {
    unsafe { DMA_COMPLETED = true; }

    unsafe {
        let dma1_ifcr = 0x50020004 as *mut u32;
        *dma1_ifcr = 0xF << (ch_idx * 4);
    }
    
}

