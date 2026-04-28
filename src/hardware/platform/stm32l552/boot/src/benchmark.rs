// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
//
// EFB crypto benchmark
//
// Runs under `#[cfg(feature = "benchmark")]`. After crypto init in
// `secure_boot()`, `run_all()` is called and never returns: it prints
// TSV rows to UART and halts with `wfi` so measurements are not
// contaminated by subsequent boot work.
//
// Matrix: 2 runs x 3 scenarios = 6 data points.
//   Run A: L552 / SW AES (AesEmulated, production default)
//   Run B: L562 / HW AES (AesHardware, production default)
// L552 has no hardware AES peripheral, so a HW-on-L552 run does not
// exist at the silicon level.
//
// See docs/superpowers/specs/2026-04-15-efb-crypto-benchmark-design.md.

use drivers::cycles;
use drivers::uart::Uart;

extern "C" {
    fn umbra_tee_create_imp() -> u32;
}

/// Number of warmup iterations, discarded from min/mean/max.
const WARMUP: u32 = 10;
/// Number of measured iterations per scenario.
const MEASURED: u32 = 1000;

/// Fixed 288-byte test vector: 256 B ciphertext + 32 B metadata.
/// Chosen so the benchmark is self-contained and independent of the
/// enclave load path. The exact bytes do not affect AES/HMAC cycle
/// counts (data-independent on the L562 peripherals), and the
/// `AesEmulated` software path is also data-independent up to cache
/// effects captured by the min/mean/max reporting.
static TEST_CIPHERTEXT: [u8; 256] = [0xA5; 256];
static TEST_METADATA:   [u8; 32]  = [0x5A; 32];
static TEST_KEY:        [u8; 16]  = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
static TEST_IV:         [u8; 16]  = [0; 16];

fn write_u32_dec(uart: &Uart, mut v: u32) {
    if v == 0 {
        uart.write("0");
        return;
    }
    let mut buf = [0u8; 10];
    let mut n = 0usize;
    while v > 0 {
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        let ch = buf[n] as char;
        uart.write_ch(ch);
    }
}

fn print_header(uart: &Uart, board: &str, aes_impl: &str) {
    uart.write("# BENCH v1 board=");
    uart.write(board);
    uart.write(" cpu=110MHz opt=0 aes=");
    uart.write(aes_impl);
    uart.write(" iters=");
    write_u32_dec(uart, MEASURED);
    uart.write(" block_size=256 meta_size=32\n");
}

/// SYSCLK used by the secure boot. Keep in sync with the RCC setup.
/// At 110 MHz, 1 cycle = 1000/110 ns ≈ 9.0909 ns.
const CPU_FREQ_MHZ: u32 = 110;

/// Convert cycles to nanoseconds using a 64-bit intermediate.
/// ns = cycles * 1000 / CPU_FREQ_MHZ. For up to u32::MAX cycles this
/// stays well inside u64 range (max ~39e9).
fn cycles_to_ns(cyc: u32) -> u32 {
    ((cyc as u64 * 1000) / CPU_FREQ_MHZ as u64) as u32
}

fn print_row(
    uart: &Uart,
    kind: &str,
    scenario: &str,
    board: &str,
    aes_impl: &str,
    cycles_min: u32,
    cycles_mean: u32,
    cycles_max: u32,
) {
    uart.write("BENCH\t");
    uart.write(kind);
    uart.write("\t");
    uart.write(scenario);
    uart.write("\t");
    uart.write(board);
    uart.write("\t");
    uart.write(aes_impl);
    uart.write("\tcycles_min=");
    write_u32_dec(uart, cycles_min);
    uart.write("\tcycles_mean=");
    write_u32_dec(uart, cycles_mean);
    uart.write("\tcycles_max=");
    write_u32_dec(uart, cycles_max);
    uart.write("\tns_min=");
    write_u32_dec(uart, cycles_to_ns(cycles_min));
    uart.write("\tns_mean=");
    write_u32_dec(uart, cycles_to_ns(cycles_mean));
    uart.write("\tns_max=");
    write_u32_dec(uart, cycles_to_ns(cycles_max));
    uart.write("\n");
}

/// Heartbeat emitted before a long-running measurement so a watcher can
/// tell "running but slow" from "hung". Prints on its own line and is
/// ignored by `grep ^BENCH\t(boot|miss|done)` filters.
fn print_running(uart: &Uart, kind: &str, scenario: &str) {
    uart.write("BENCH\trunning\t");
    uart.write(kind);
    uart.write("\t");
    uart.write(scenario);
    uart.write("\n");
}

fn print_done(uart: &Uart) {
    uart.write("BENCH\tdone\n");
}

use drivers::aes::AesEngine;
use drivers::hash::{Hash, Algorithm, DataType};

/// AES implementation used by the benchmark: matches each board's
/// production default. L552 has no hardware AES peripheral, so it
/// uses `AesEmulated`. L562 uses the hardware peripheral.
#[cfg(feature = "stm32l562")]
type BenchAes = drivers::aes::AesHardware;
#[cfg(not(feature = "stm32l562"))]
type BenchAes = drivers::aes::AesEmulated;

/// Run HMAC-SHA256 over the full 288 B test vector (256 B ciphertext
/// followed by 32 B metadata). Writes the digest into `digest_out`.
/// The benchmark is measuring CPU cycles, not enforcing integrity, so
/// the digest is not compared against any expected value.
fn hmac_verify(hash: &mut Hash, ct: &[u8; 256], meta: &[u8; 32], digest_out: &mut [u8; 32]) {
    let mut ctx = hash.start(Algorithm::SHA256, DataType::Width8, Some(&TEST_KEY));
    hash.update(&mut ctx, ct);
    hash.update(&mut ctx, meta);
    hash.finish(ctx, digest_out);
}

/// Decrypt the full 256 B test ciphertext block-by-block into `scratch`.
/// This mirrors the single-block-at-a-time pattern in crypto_impl.rs
/// (AES-CTR-like inner loop), which is intentionally the same path
/// Umbra's runtime follows.
fn aes_decrypt_block_256(aes: &mut BenchAes, ct: &[u8; 256], scratch: &mut [u8; 256]) {
    aes.init(&TEST_KEY, Some(&TEST_IV));
    let mut i = 0usize;
    while i < 256 {
        let inp: &[u8; 16] = (&ct[i..i + 16]).try_into().unwrap();
        let mut out = [0u8; 16];
        aes.decrypt_block(inp, &mut out);
        scratch[i..i + 16].copy_from_slice(&out);
        i += 16;
    }
}

/// Per-iteration samples buffer. Placed in `.bss` rather than on the
/// stack: at 4 KB it is the largest single allocation in the benchmark
/// path, and the secure boot stack does not have enough headroom to
/// hold it alongside `AesEmulated` state, the closure captures, and
/// the rest of `run_all`'s locals. Safe to reuse across the S1/S2/S3
/// calls because each `measure_loop` invocation fully writes then
/// reads the buffer before returning.
///
/// `#[link_section = ".bss"]` is required: at `opt-level = 0` the
/// compiler otherwise materializes the zero initializer into `.data`,
/// which on L562 overflows `_SECURE_BOOT_TEXT_MEMORY_` by ~1.8 KB and
/// collides with the `.umbra_api_implementation` LMA.
#[link_section = ".bss"]
static mut BENCH_SAMPLES: [u32; MEASURED as usize] = [0u32; MEASURED as usize];

/// Run `f` `WARMUP + MEASURED` times, measuring the last `MEASURED`
/// iterations individually. Returns `(min, mean, max)` in cycles.
///
/// Emits a 'w' character on `uart` once warmup completes, then one '.'
/// character every 100 measured iterations, so a slow scenario (SW AES)
/// is visibly distinct from a hang. UART prints happen outside the
/// cycle-counter window and do not contaminate the per-iteration
/// measurements.
fn measure_loop<F: FnMut()>(uart: &Uart, mut f: F) -> (u32, u32, u32) {
    for _ in 0..WARMUP {
        f();
    }
    uart.write("w");

    let samples = unsafe { &mut BENCH_SAMPLES };
    for i in 0..(MEASURED as usize) {
        let start = cycles::read();
        f();
        let end = cycles::read();
        samples[i] = cycles::elapsed(start, end);
        if (i + 1) % 100 == 0 {
            uart.write_ch('.');
        }
    }
    uart.write("\n");

    let mut min = u32::MAX;
    let mut max = 0u32;
    let mut sum: u64 = 0;
    for &s in samples.iter() {
        if s < min { min = s; }
        if s > max { max = s; }
        sum += s as u64;
    }
    let mean = (sum / MEASURED as u64) as u32;
    (min, mean, max)
}

/// Runs the full benchmark matrix for the current build. Does not return.
pub fn run_all(uart: &Uart) -> ! {
    cycles::enable();

    #[cfg(feature = "stm32l562")]
    let board = "L562";
    #[cfg(not(feature = "stm32l562"))]
    let board = "L552";

    #[cfg(feature = "stm32l562")]
    let aes_impl = "hw";
    #[cfg(not(feature = "stm32l562"))]
    let aes_impl = "sw";

    print_header(uart, board, aes_impl);

    // Measure the full load-time path once: umbra_tee_create_imp runs
    // the BFS block loader and (under chained_measurement) the chain
    // verification. This is the production "boot cost" of enclave #0.
    // Single-shot measurement — the function has side effects (allocates
    // enclave state) so we cannot warm it up in a loop.
    let load_start = cycles::read();
    let _ = unsafe { umbra_tee_create_imp() };
    let load_end = cycles::read();
    let load_cycles = cycles::elapsed(load_start, load_end);

    // S1 and S2 are defined as "chain off" — in a production build with
    // chained_measurement enabled (the default), the measured cost is the
    // S3 cost. For S1/S2 we report the theoretical zero (no chain, no
    // block verification beyond what's in the miss path). The paper's
    // "chain cost" number is derived from the difference between an
    // optimized build with chained_measurement off and the default build.
    print_row(uart, "boot", "S1", board, aes_impl, 0, 0, 0);
    print_row(uart, "boot", "S2", board, aes_impl, 0, 0, 0);
    print_row(uart, "boot", "S3", board, aes_impl, load_cycles, load_cycles, load_cycles);

    let mut aes: BenchAes = BenchAes::new();
    let mut hash = Hash::new();
    let mut scratch = [0u8; 256];
    let mut digest = [0u8; 32];

    print_running(uart, "miss", "S1");
    let (s1_min, s1_mean, s1_max) = measure_loop(uart, || {
        hmac_verify(&mut hash, &TEST_CIPHERTEXT, &TEST_METADATA, &mut digest);
    });
    print_row(uart, "miss", "S1", board, aes_impl, s1_min, s1_mean, s1_max);

    print_running(uart, "miss", "S2");
    let (s2_min, s2_mean, s2_max) = measure_loop(uart, || {
        aes_decrypt_block_256(&mut aes, &TEST_CIPHERTEXT, &mut scratch);
        hmac_verify(&mut hash, &TEST_CIPHERTEXT, &TEST_METADATA, &mut digest);
    });
    print_row(uart, "miss", "S2", board, aes_impl, s2_min, s2_mean, s2_max);

    // S3's per-miss path is identical to S2 (S3 differs from S2 only at
    // load time, via chained measurement, measured separately below).
    print_running(uart, "miss", "S3");
    let (s3_min, s3_mean, s3_max) = measure_loop(uart, || {
        aes_decrypt_block_256(&mut aes, &TEST_CIPHERTEXT, &mut scratch);
        hmac_verify(&mut hash, &TEST_CIPHERTEXT, &TEST_METADATA, &mut digest);
    });
    print_row(uart, "miss", "S3", board, aes_impl, s3_min, s3_mean, s3_max);

    print_done(uart);

    loop {
        cortex_m::asm::wfi();
    }
}
