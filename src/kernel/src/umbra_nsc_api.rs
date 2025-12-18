
//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>                       //
// Description:                                                                     //
//      TBD
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

use core::arch::global_asm;
use super::memory_protection_server::memory_guard::MemorySecurityGuardTrait;
use super::common::memory_layout::MemoryBlockList;
use super::common::memory_layout::MemoryBlockSecurityAttribute;
use super::common::enclave::UmbraEnclaveHeader;
use super::common::enclave::UMBRA_HEADER_SIZE;

global_asm!(
    "
    .section .umbra_nsc_api, \"a\"
    "
);

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn umbra_tee_create();
}
#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .global umbra_tee_create 
    .extern umbra_tee_create_imp    

    umbra_tee_create:
        sg
        push {{lr}}
        bl umbra_tee_create_imp
        pop {{lr}}
        bxns lr
    "
);
#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn umbra_enclave_run();
}
#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .global umbra_enclave_run 
    .extern umbra_enclave_run_imp    

    umbra_enclave_run:
        sg
        push {{lr}}
        bl umbra_enclave_run_imp
        pop {{lr}}
        bxns lr
    "
);
////////////////////////////////////////////////////////

global_asm!(
    "
    .section .umbra_api_implementation, \"a\"
    "
);
unsafe fn dump_binary(src_addr: u32, dst_addr: u32, size: u32) {
    let src_ptr = src_addr as *const u8;
    let dst_ptr = dst_addr as *mut u8;
    
    for i in 0..size {
        let byte = core::ptr::read_volatile(src_ptr.add(i as usize));
        core::ptr::write_volatile(dst_ptr.add(i as usize), byte);
    }
}

// Let's assume a fixed address, 0x20000000
// This region must be defined as secure
// NB see RM0438, it looks like 0x20000000 can't be secure
const EFBC_BASE: u32 = 0x20030200;
const EFBC_SIZE: u32 = 0x8000;  // 32KB

#[no_mangle]
pub fn umbra_tee_create_imp() -> u32{

    let enclave_flash_addr: u32 = 0x08078000;

    
    let efbc_base: u32 = EFBC_BASE;
    let size: u32 = 0x100;

    let header = unsafe {
        match UmbraEnclaveHeader::from_address(enclave_flash_addr) {
            Some(h) => h,
            None => {
                return 0xFFFFFFFF;
            }
        }
    };

    let code_flash_addr = enclave_flash_addr + UMBRA_HEADER_SIZE;
    let code_size = header.code_size;
    if code_size > EFBC_SIZE {
        return 0xFFFFFFFD; 
    }
    unsafe{
        dump_binary(code_flash_addr, efbc_base, code_size);
    }
    0
}


#[no_mangle]
pub fn umbra_enclave_run_imp() -> u32 {

    // Recupera l'entry point dell'enclave
    let entry_point: u32 = EFBC_BASE;

    let result: u32;
    unsafe {
        // let enclave_fn: extern "C" fn() -> u32 = core::mem::transmute(entry_point | 0x1);
        // result = enclave_fn();
        // Ensure Thumb state and branch in Secure world (use BLX, not BLXNS)
        let entry_point_thumb: u32 = entry_point | 1;
        core::arch::asm!(
            "blx {0}",
            in(reg) entry_point_thumb,
            lateout("r0") result,
            clobber_abi("C")
        );
    }
    return result;
}




