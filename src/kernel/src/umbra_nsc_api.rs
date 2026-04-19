
//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>                       //
// Description:                                                                     //
//      Non-Secure Callable (NSC) API veneers for Umbra TEE calls.                  //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

use core::arch::global_asm;

global_asm!(
    "
    .section .umbra_nsc_api, \"a\"
    "
);

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn umbra_tee_create(base_addr: u32) -> u32;
}
#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .global umbra_tee_create 
    .extern umbra_tee_create_imp    

    umbra_tee_create:
        sg
        push {{r4, lr}}
        bl umbra_tee_create_imp
        pop {{r4, lr}}
        bxns lr
    "
);
#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn umbra_enclave_run();
    pub fn umbra_debug_print(str_ptr: *const u8);
}
#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .global umbra_enclave_run 
    .extern umbra_enclave_run_imp    

    umbra_enclave_run:
        sg
        push {{r4, lr}}
        bl umbra_enclave_run_imp
        pop {{r4, lr}}
        bxns lr
    "
);

#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .global umbra_debug_print
    .extern umbra_debug_print_imp

    umbra_debug_print:
        sg
        push {{r4, lr}}
        bl umbra_debug_print_imp
        pop {{r4, lr}}
        bxns lr
    "
);

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn umbra_enclave_enter(enclave_id: u32) -> u32;
    pub fn umbra_enclave_exit(enclave_id: u32) -> u32;
    pub fn umbra_enclave_status(enclave_id: u32) -> u32;
}
#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .global umbra_enclave_enter
    .extern umbra_enclave_enter_imp

    umbra_enclave_enter:
        sg
        push {{r4, lr}}
        bl umbra_enclave_enter_imp
        pop {{r4, lr}}
        bxns lr
    "
);

#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .global umbra_enclave_exit
    .extern umbra_enclave_exit_imp

    umbra_enclave_exit:
        sg
        push {{r4, lr}}
        bl umbra_enclave_exit_imp
        pop {{r4, lr}}
        bxns lr
    "
);

#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .global umbra_enclave_status
    .extern umbra_enclave_status_imp

    umbra_enclave_status:
        sg
        push {{r4, lr}}
        bl umbra_enclave_status_imp
        pop {{r4, lr}}
        bxns lr
    "
);

////////////////////////////////////////////////////////

global_asm!(
    "
    .section .umbra_api_implementation, \"a\"
    "
);

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn umbra_tee_create_imp(base_addr: u32) -> u32;
    pub fn umbra_enclave_run_imp() -> u32;
    pub fn umbra_debug_print_imp(str_ptr: *const u8);
    pub fn umbra_enclave_enter_imp(enclave_id: u32) -> u32;
    pub fn umbra_enclave_exit_imp(enclave_id: u32) -> u32;
    pub fn umbra_enclave_status_imp(enclave_id: u32) -> u32;
}

// NOTE: Implementations have moved to boot crate.
// The veneers above (umbra_tee_create/umbra_enclave_run) branch to these external symbols.
