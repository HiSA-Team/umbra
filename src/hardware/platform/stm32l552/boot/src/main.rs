
//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>                       //
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

use core::arch::global_asm;
//use core::arch::asm;

// Local Modules

// Platform-related crates
#[allow(unused_imports)]
use arm::startup;
use arm::sau;
use drivers::gtzc;

// Umbra Kernel-related crates
use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;
use kernel::common::memory_layout::MemoryBlockList;
use kernel::common::memory_layout::MemoryBlockSecurityAttribute;

#[no_mangle]
#[allow(dead_code)]
#[allow(unreachable_code)]
#[allow(unused_assignments)]

pub unsafe fn secure_boot() -> !{

    //////////////////////////////
    // INITIALIZE MEMORY GUARDS //
    //////////////////////////////

    let mut sau_driver : sau::SauDriver = sau::SauDriver::new();
    let mut gtzc_driver : gtzc::GtzcDriver = gtzc::GtzcDriver::new();
    sau_driver.memory_security_guard_init();
    gtzc_driver.memory_security_guard_init();

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

    let mut memory_block_list = MemoryBlockList::create_from_range(0x08040000,0x08080000);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
    sau_driver.memory_security_guard_create(&memory_block_list);

    /////////////////////////////////////
    // CONFIGURE NON-SECURE DATA - SAU //
    /////////////////////////////////////

    // Let's use region 1 to define the whole SRAM1 as Non-secure
    memory_block_list = MemoryBlockList::create_from_range(0x20000000,0x2002ffe0);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
    sau_driver.memory_security_guard_create(&memory_block_list);

    /////////////////////////////////////////////////
    // CONFIGURE NON-SECURE DATA - SRAM CONTROLLER //
    /////////////////////////////////////////////////

    // Similarly to Flash controller, SRAM pages are defined secure by default.
    // It means that even if the SAU marks the SRAM1 as non-secure, the SRAM
    // Controller would generate a Bus exception. therefore, we must also
    // Instruct the SRAM controller to allow SRAM1 accesses from non-secure code.

    // Check Memory Protection Controller Block Based (MPCBB)
    // A block is 256 Bytes in size, A superblock is 256x32 = 8KB
    // SRAM1 is made of 192/8=24 super blocks, while SRAM2 has 8 superblocks

    // Reset all block security bits To make all blocks non-secure for SRAM1
    memory_block_list = MemoryBlockList::create_from_range(0x20000000,0x20030000);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
    gtzc_driver.memory_security_guard_create(&memory_block_list);

    ///////////////////////////////////
    // CONFIGURE NON-SECURE CALLABLE //
    ///////////////////////////////////

    // Configure the non-secure callable region here
    memory_block_list = MemoryBlockList::create_from_range(0x08030000,0x0803ffe0);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::TrustedGateway);
    sau_driver.memory_security_guard_create(&memory_block_list);

    /////////////////////////////////////
    // Jump to Non-Secure World        //
    /////////////////////////////////////

    trampoline_to_ns();
    
    loop {}

}


#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    // The trampoline function is used to jump to the
    // host entry point, which is defined in the linker
    // script.
    pub fn trampoline_to_ns();
}
#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .section .text
    .global trampoline_to_ns
    .extern _host_entry_point     

    trampoline_to_ns:
        ldr r0, =_host_entry_point      // Load the address of ns_fn 
        movs r1, #1
        bics r0, r1                     // Clear bit 0 of address in r0 
        blxns r0                        // Branch to the non-secure function 

    "
);
