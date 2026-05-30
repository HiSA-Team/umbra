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
    pub fn umbra_enclave_create(base_addr: u32) -> u32;
    pub fn umbra_debug_print(str_ptr: *const u8);
    pub fn umbra_enclave_enter(enclave_id: u32) -> u32;
    pub fn umbra_enclave_exit(enclave_id: u32) -> u32;
    pub fn umbra_enclave_status(enclave_id: u32) -> u32;
    /// dump Secure-side accumulators (boot + switch
    /// cycles) to UART. Always-present veneer; no-op when the kernel
    /// is built without `bench-eval`. Cost when off: one SVC + bxns.
    pub fn umbra_bench_dump();
    /// baseline (Stage A Step 4): empty NSC veneer.
    /// The Secure side does nothing — used to measure the TrustZone
    /// fixed cost (SG + bxns + register barrier) for the switch-plot
    /// baseline. NS host brackets this with DWT reads and divides
    /// every switch-cell measurement by the observed null cycles.
    pub fn umbra_null_call();
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn umbra_enclave_create_imp(base_addr: u32) -> u32;
    pub fn umbra_debug_print_imp(str_ptr: *const u8);
    pub fn umbra_enclave_enter_imp(enclave_id: u32) -> u32;
    pub fn umbra_enclave_exit_imp(enclave_id: u32) -> u32;
    pub fn umbra_enclave_status_imp(enclave_id: u32) -> u32;
    pub fn umbra_bench_dump_imp();
}
