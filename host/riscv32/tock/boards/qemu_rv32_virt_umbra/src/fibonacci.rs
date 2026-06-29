//! Demo enclave payload embedded in the Tock board image: Tock drives the Umbra
//! enclave API as the untrusted S-mode loader. Identical computation to the
//! bare-metal host's `app/fibonacci.rs`: `fibonacci()` returns `0x72CA33A8`.
//! The `dummy_filler_*` functions push the code past one EFB block so the
//! multi-block loader path is exercised; the 48-byte `ENCLAVE_HEADER` (magic
//! `"UMBR"`) precedes the code so the monitor's `tee_create` finds it. The blob
//! is AES-CTR-encrypted + chain-HMAC-signed in place by `tools/protect_enclave.py`
//! at build time, with the same master key the monitor embeds.

/// 48-byte enclave header (magic, trust level, sizes, 32-byte HMAC placeholder
/// that `protect_enclave.py` overwrites).
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
    // HMAC (32 bytes) — overwritten by protect_enclave.py
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

/// Enclave entry — placed FIRST in `.app.enclave_code` (lands at `base + 48`).
/// The monitor `mret`s here in U-mode; when it returns the monitor catches the
/// fetch at the return sentinel and reads the result from `a0`. The long spin
/// makes the enclave span several preemption quanta, so Tock (the S-mode loader)
/// observes the suspend → re-enter → resume cycle.
#[link_section = ".app.enclave_entry"]
#[no_mangle]
pub extern "C" fn fibonacci() -> i32 {
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

    // Span several preemption quanta so the loader sees suspend/resume.
    let mut spin: u32 = 0;
    while spin < 6_000_000 {
        spin = core::hint::black_box(spin).wrapping_add(1);
    }
    core::hint::black_box(spin);

    next_term // expected: 0x72CA33A8
}
