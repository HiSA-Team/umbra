//! Demo enclave payload for the RISC-V port. The enclave code is deliberately compute-heavy to
//! `fibonacci()` returns `0x72CA33A8`; the `dummy_filler_*` functions exist only
//! to push the code size past one block so the multi-block loader path is
//! exercised. The 48-byte `ENCLAVE_HEADER` (magic `"UMBR"`) precedes the code so
//! the host's flash scan finds it.

/// 48-byte enclave header (mirrors the C `enclave_header`): magic, trust level,
/// sizes, and a 32-byte HMAC.
#[link_section = ".app.enclave_header"]
#[no_mangle]
#[used]
pub static ENCLAVE_HEADER: [u8; 48] = [
    0x55, 0x42, 0x4D, 0x52, // Magic: "UMBR" (little-endian 0x524D4255)
    0x01, // trust_level (Trusted)
    0x00, // reserved
    0x01, 0x00, // efbc_size
    0x00, 0x00, // ess_blocks
    0x00, 0x04, 0x00, 0x00, // code_size (1024)
    0x00, 0x00, // reserved
    // HMAC (32 bytes)
    0x37, 0x49, 0x09, 0xC7, 0x44, 0xB8, 0xD9, 0xA6, 0x9E, 0x8C, 0x2C, 0xF3, 0x41, 0x64, 0x0E, 0x57,
    0x55, 0x32, 0xC0, 0xB7, 0xDF, 0x49, 0x83, 0x98, 0xCC, 0xC8, 0x30, 0x59, 0x03, 0xCC, 0xD9, 0x36,
];

#[link_section = ".app.enclave_code"]
#[no_mangle]
pub extern "C" fn heavy_computation(val: i32) -> i32 {
    let mut x = core::hint::black_box(val);
    x = x.wrapping_mul(1664525).wrapping_add(1013904223);
    x = x.wrapping_shl(13) ^ x;
    x = x.wrapping_mul(1664525).wrapping_add(1013904223);
    if x % 2 == 0 {
        x = x.wrapping_add(1);
    } else {
        x = x.wrapping_sub(1);
    }
    x = x.wrapping_mul(1664525).wrapping_add(1013904223);
    x = x.wrapping_shl(13) ^ x;
    x
}

#[link_section = ".app.enclave_code"]
#[no_mangle]
pub extern "C" fn dummy_filler_a(val: &mut i32) {
    *val = val.wrapping_add(1);
    *val = heavy_computation(*val);
    *val ^= 0xAAAA_AAAAu32 as i32;
    *val = heavy_computation(*val);
}

#[link_section = ".app.enclave_code"]
#[no_mangle]
pub extern "C" fn dummy_filler_b(val: &mut i32) {
    *val = val.wrapping_add(2);
    *val = heavy_computation(*val);
    *val ^= 0x5555_5555;
    *val = heavy_computation(*val);
}

#[link_section = ".app.enclave_code"]
#[no_mangle]
pub extern "C" fn dummy_filler_c(val: &mut i32) {
    *val = val.wrapping_add(3);
    *val = heavy_computation(*val);
    *val ^= 0xFF00_FF00u32 as i32;
    *val = heavy_computation(*val);
}

/// Enclave entry — a plain function placed FIRST in the enclave code (so it
/// lands at `base + 48`). The monitor `mret`s here in U-mode with `ra` set to a
/// return sentinel; when `fibonacci` returns, the monitor catches it and reads
/// the result from `a0`. The enclave never calls an exit ecall — Umbra handles
/// the exit, exactly as the L552 EFB model does.
#[link_section = ".app.enclave_entry"]
#[no_mangle]
pub extern "C" fn fibonacci() -> i32 {
    #[cfg(feature = "neg_iso_enc")]
    {
        // SAFETY: deliberately forbidden — the U-mode enclave must trap reading
        // the S-mode host region; the monitor's fault dump shows V=80100000.
        let _ = unsafe { core::ptr::read_volatile(0x8010_0000 as *const u32) };
    }

    let n = 12;
    let mut t1: i32 = 0;
    let mut t2: i32 = 1;
    let mut next_term = t1.wrapping_add(t2);

    t1 = heavy_computation(t1);
    dummy_filler_a(&mut t1);

    t2 = heavy_computation(t2);
    dummy_filler_b(&mut t2);

    let mut i = 3;
    while i <= n {
        t1 = t2;
        t2 = next_term;

        dummy_filler_c(&mut t1);

        if t1 > 100_000 {
            t1 = 0; // prevent overflow
        }

        next_term = t1.wrapping_add(t2);
        i += 1;
    }

    // Preemption-demo delay: spin long enough that the enclave spans several
    // M-mode timer quanta, so the host observes the suspend → re-enter → resume
    // cycle. `black_box` stops the optimiser from eliding it; it never touches
    // `next_term`, so the result stays 0x72CA33A8. The `spin` counter lives in a
    // register that the monitor saves/restores across each preemption.
    let mut spin: u32 = 0;
    while spin < 6_000_000 {
        spin = core::hint::black_box(spin).wrapping_add(1);
    }
    core::hint::black_box(spin);

    next_term // expected: 0x72CA33A8
}
