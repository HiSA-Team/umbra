//! RISC-V (RV32) bare-metal Umbra host — the Rust counterpart of the STM32L552
//! bare-metal host (`host/stm32l552/bare_metal/src/main.c`).
//!
//! It runs in U-mode, embeds an enclave (see `app/fibonacci.rs`), and drives the
//! same flow as the L552 host: scan for enclave headers, `create` each, then
//! loop `enter`-ing them and acting on the returned status. The Umbra API
//! (`umbra_enclave_create` / `umbra_debug_print` / `umbra_enclave_enter` /
//! `umbra_enclave_status`) is identical to the L552 host's; only its transport
//! changes — NSC veneers become `ecall`s (see `umbra_api`).
#![no_std]
#![no_main]

mod umbra_api;

#[path = "../app/fibonacci.rs"]
mod fibonacci;

use umbra_api::{
    umbra_debug_print, umbra_enclave_create, umbra_enclave_enter, umbra_enclave_status,
    umbra_u32_to_hex,
};

core::arch::global_asm!(include_str!("startup.S"));

const PAGE_SIZE: u32 = 0x1000;
const UMBRA_MAGIC: u32 = 0x524D_4255; // "UMBR" little-endian
const MAX_ENCLAVES: usize = 4;
const NS_FLASH_END: u32 = 0x8018_0000; // end of the SHARED enclave+scan SPMP region

const STATUS_SUSPENDED: u32 = 3;
const STATUS_TERMINATED: u32 = 4;
const STATUS_FAULTED: u32 = 5;

extern "C" {
    static _enclave_start: u8;
}

#[no_mangle]
pub extern "C" fn host_main() -> ! {
    umbra_debug_print("[USER] Hello Untrusted World!\n");

    #[cfg(feature = "neg_iso_host")]
    {
        umbra_debug_print("[NEG-ISO] host(S) probing ESS 0x80200000\n");
        // SAFETY: deliberately forbidden — the monitor must trap this access.
        let _ = unsafe { core::ptr::read_volatile(0x8020_0000 as *const u32) };
        umbra_debug_print("[NEG-ISO] FAIL: host read ESS without trapping\n");
        loop { core::hint::spin_loop(); }
    }

    let mut enclave_ids = [0u32; MAX_ENCLAVES];
    let mut enclave_count: usize = 0;

    // Scan host memory for enclave headers, page by page, from `_enclave_start`.
    let scan_start = (core::ptr::addr_of!(_enclave_start) as u32) & !(PAGE_SIZE - 1);
    let mut addr = scan_start;
    while addr < NS_FLASH_END && enclave_count < MAX_ENCLAVES {
        // SAFETY: scanning the host's own image for the enclave magic word.
        let magic = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if magic == UMBRA_MAGIC {
            let id = umbra_enclave_create(addr);
            if id < 0xFFFF_FFF0 {
                enclave_ids[enclave_count] = id;
                enclave_count += 1;
                umbra_debug_print("[USER] Enclave created\n");
            } else {
                umbra_debug_print("[USER] Enclave creation REJECTED\n");
            }
        }
        addr += PAGE_SIZE;
    }

    if enclave_count == 0 {
        umbra_debug_print("[USER] No enclaves found\n");
        loop {
            core::hint::spin_loop();
        }
    }

    let mut active = enclave_count;
    while active > 0 {
        for i in 0..enclave_count {
            if enclave_ids[i] == 0 {
                continue;
            }

            let ret = umbra_enclave_enter(enclave_ids[i]);
            let status = (ret >> 8) & 0xFF;
            let mut hex_buf = [0u8; 11];

            match status {
                STATUS_SUSPENDED => {
                    umbra_debug_print("[USER] Enclave preempted (timer), re-entering\n");
                }
                STATUS_TERMINATED => {
                    let full_result = umbra_enclave_status(enclave_ids[i]);
                    umbra_debug_print("[USER] Enclave terminated! R0=");
                    umbra_debug_print(umbra_u32_to_hex(full_result, &mut hex_buf));
                    umbra_debug_print("\n");
                    enclave_ids[i] = 0;
                    active -= 1;
                }
                STATUS_FAULTED => {
                    umbra_debug_print("[USER] Enclave faulted — ret=");
                    umbra_debug_print(umbra_u32_to_hex(ret, &mut hex_buf));
                    umbra_debug_print("\n");
                    enclave_ids[i] = 0;
                    active -= 1;
                }
                _ => {}
            }
        }
    }

    umbra_debug_print("[USER] All enclaves done\n");
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
