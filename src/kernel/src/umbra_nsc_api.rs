
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
        bl umbra_tee_create_imp

    "
);

////////////////////////////////////////////////////////

global_asm!(
    "
    .section .umbra_api_implementation, \"a\"
    "
);

#[no_mangle]
pub fn umbra_tee_create_imp(){

    // Let's assume a fixed address, 0x20000000
    // This region must be defined as secure
    let mut base_addr: u32 = 0x20000000;
    let size: u32 = 0x100;

    // Define secure memory regions
    //base_addr = base_addr + size;


    // Copy the binary 

    

    //loop {}
}







