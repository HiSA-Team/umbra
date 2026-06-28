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

#[cfg(feature = "gateway_demo")]
extern "C" {
    static _utask_base: u8;
    static _ustack_top: u8;
    static _gw_secret: u8;
}

/// U-task-local UART print: one `ecall` per byte (id 3 = debug). MUST live in
/// `.utask` — the U-task is sPMP-fenced to its own code+stack windows, so both
/// the bytes it reads (`bytes`) and the code it fetches (this helper) have to be
/// inside the granted region, never in the host's `.text`/`.rodata`. (The host's
/// `umbra_debug_print` reads the string in-place, which from U-mode would fault
/// because string literals land in the host `.rodata` outside the grant.)
#[cfg(feature = "gateway_demo")]
#[link_section = ".utask"]
fn utask_print(bytes: &[u8]) {
    for &b in bytes {
        // SAFETY: debug-print ecall from U-mode; the monitor prints a0's byte.
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a7") 3u32,
                inlateout("a0") b as u32 => _,
                options(nostack),
            );
        }
    }
}

// Messages live in `.utask` (granted R) so the fenced U-task can read them. Sized
// from the literal so the length can never drift.
#[cfg(feature = "gateway_demo")]
#[link_section = ".utask"]
static GW_MSG_GRANTED: [u8; b"[GW] u-task: reading granted region\n".len()] =
    *b"[GW] u-task: reading granted region\n";
#[cfg(feature = "gateway_demo")]
#[link_section = ".utask"]
static GW_MSG_OK: [u8; b"[GW] param read OK\n".len()] = *b"[GW] param read OK\n";
#[cfg(feature = "gateway_demo")]
#[link_section = ".utask"]
static GW_MSG_FAIL: [u8; b"[GW] FAIL: secret read without trapping\n".len()] =
    *b"[GW] FAIL: secret read without trapping\n";

/// U-task entry — runs in U-mode, fenced by the sPMP the monitor shadowed from
/// the guest's PMP writes. Reads its granted region (OK) then the ungranted
/// secret (must trap with a page fault, C=0xd).
#[cfg(feature = "gateway_demo")]
#[link_section = ".utask"]
#[no_mangle]
pub extern "C" fn utask_entry() -> ! {
    utask_print(&GW_MSG_GRANTED);
    // SAFETY: _utask_base is granted R-X to U via the shadowed sPMP entry.
    let _ok = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(_utask_base) as *const u32) };
    utask_print(&GW_MSG_OK);
    // SAFETY: deliberately forbidden — _gw_secret was never granted to the U-task.
    let _bad = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(_gw_secret) as *const u32) };
    utask_print(&GW_MSG_FAIL);
    loop { core::hint::spin_loop(); }
}

/// Smstateen probe: the S-guest attempts a DIRECT sPMP indirect-CSR write
/// (`csrw siselect`). With the monitor's mstateen0 bit-60 (SVSLCT) cleared this
/// traps to M and the gateway denies it — the monitor prints
/// "[GW] denied direct guest sPMP write" and the write never takes effect (the
/// pass signal is that monitor line). If the gate were inert the `csrw` would
/// execute silently and only the line below would appear.
#[cfg(feature = "gateway_evil")]
fn gateway_evil() -> ! {
    // SAFETY: deliberately probing the gateway; the access must be trapped+denied
    // by the monitor, not executed.
    unsafe { core::arch::asm!("csrw 0x150, x0", options(nostack)) }; // siselect <- 0
    umbra_debug_print("[GW-EVIL] direct sPMP attempt returned to S\n");
    loop { core::hint::spin_loop(); }
}

/// The S-mode guest acting as a fake-M OS: program PMP for its U-task, then sret
/// into it. The PMP writes trap to Umbra and become clamped sPMP UMODE entries.
#[cfg(feature = "gateway_demo")]
fn gateway_demo() -> ! {
    use core::arch::asm;
    let code = core::ptr::addr_of!(_utask_base) as u32;
    let stack = core::ptr::addr_of!(_ustack_top) as u32;
    // NAPOT helper: pmpaddr = (base>>2) | ((size>>3)-1); size = 64 KB here.
    let napot = |base: u32| (base >> 2) | ((0x1_0000u32 >> 3) - 1);
    // R|X NAPOT for the code (cfg byte 0b0001_1101 = R|X|NAPOT), R|W for stack.
    const RX_NAPOT: u32 = 0b001 | 0b100 | (0b11 << 3);
    const RW_NAPOT: u32 = 0b001 | 0b010 | (0b11 << 3);
    // SAFETY: these PMP CSR writes are illegal from S and trap to the M-mode
    // gateway, which shadows them into sPMP. pmpaddr0/pmpcfg0 entry 0; entry 1.
    unsafe {
        asm!("csrw pmpaddr0, {a}", a = in(reg) napot(code));
        asm!("csrw pmpaddr1, {a}", a = in(reg) napot(stack));
        // pmpcfg0 packs entry0 (byte0) + entry1 (byte1).
        let cfg = RX_NAPOT | (RW_NAPOT << 8);
        asm!("csrw pmpcfg0, {c}", c = in(reg) cfg);
        // sret into the U-task: SPP=0 (U), sepc=utask, sp=ustack_top.
        let utask = utask_entry as usize;
        asm!(
            "csrc sstatus, {spp}",      // clear SPP -> sret returns to U
            "csrw sepc, {pc}",
            "mv sp, {sp}",
            "sret",
            spp = in(reg) 1u32 << 8,    // sstatus.SPP = bit 8
            pc = in(reg) utask,
            sp = in(reg) stack,
            options(noreturn),
        );
    }
}

#[no_mangle]
pub extern "C" fn host_main() -> ! {
    umbra_debug_print("[USER] Hello Untrusted World!\n");

    #[cfg(feature = "gateway_demo")]
    {
        gateway_demo();
    }

    #[cfg(feature = "gateway_evil")]
    {
        gateway_evil();
    }

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
