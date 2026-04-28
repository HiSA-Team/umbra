//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>                       //
// Description:                                                                     //
//      Non-Secure Callable (NSC) API declarations.                                 //
//      Assembly veneers live in asm/arm/nsc_veneers.s (compiled via build.rs).      //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn umbra_tee_create(base_addr: u32) -> u32;
    pub fn umbra_debug_print(str_ptr: *const u8);
    pub fn umbra_enclave_enter(enclave_id: u32) -> u32;
    pub fn umbra_enclave_exit(enclave_id: u32) -> u32;
    pub fn umbra_enclave_status(enclave_id: u32) -> u32;
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn umbra_tee_create_imp(base_addr: u32) -> u32;
    pub fn umbra_debug_print_imp(str_ptr: *const u8);
    pub fn umbra_enclave_enter_imp(enclave_id: u32) -> u32;
    pub fn umbra_enclave_exit_imp(enclave_id: u32) -> u32;
    pub fn umbra_enclave_status_imp(enclave_id: u32) -> u32;
}
