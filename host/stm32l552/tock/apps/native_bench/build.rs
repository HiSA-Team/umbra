//! native baseline TBF builder, per-bench mode.
//!
//! Exactly ONE `bench_<name>` Cargo feature is active per build (the
//! harness in tools/run_native_baseline.sh rebuilds and reflashes the
//! TBF for each of the 13 TACLeBench mains). This keeps the binary
//! tiny — each bench's .text + static data is well under 32 KB — and
//! avoids merging 13 sets of conflicting `main` symbols, global state,
//! and large input arrays into a single firmware that would overflow
//! the standard 32 KB APPS_NS region.
//!
//! Same build flags as the enclave Makefile (`-O0 -march=armv8-m.main
//! -mthumb -nostdinc -nostdlib`) for fair cycle-count comparison, but
//! WITHOUT `-fpic`/`-fvisibility=hidden` (native execution uses
//! libtock-rs's real loader, no enclave-blob constraint), and with
//! `-Dmain=<bench>_unused_main` so the bench's top-level `main` wrapper
//! doesn't conflict with the libtock-rs runtime's `start`/`main` symbols
//! (we call the `_init/_main/_return` triplet directly from Rust).

use std::path::PathBuf;

fn main() {
    let has_addrs = std::env::var("LIBTOCK_LINKER_FLASH").is_ok()
        && std::env::var("LIBTOCK_LINKER_RAM").is_ok();
    let has_platform = std::env::var("LIBTOCK_PLATFORM").is_ok();

    if !(has_addrs || has_platform) {
        println!("cargo:rerun-if-env-changed=LIBTOCK_LINKER_FLASH");
        println!("cargo:rerun-if-env-changed=LIBTOCK_LINKER_RAM");
        println!("cargo:rerun-if-env-changed=LIBTOCK_PLATFORM");
        return;
    }

    libtock_build_scripts::auto_layout();

    let tacle = PathBuf::from("../../../taclebench");
    let kernel = tacle.join("lib/tacle-bench/bench/kernel");
    let seq = tacle.join("lib/tacle-bench/bench/sequential");
    let blob_src = tacle.join("blob_src");
    let bare = PathBuf::from("../../../bare_metal");

    println!("cargo:rerun-if-changed={}", blob_src.display());
    println!("cargo:rerun-if-changed={}", bare.join("app/fibonacci.c").display());

    // libc shim is always linked — memcpy/memset/EABI aliases are
    // needed by every bench. Unused entries get `--gc-sections`'d.
    {
        let mut b = base_build();
        b.file(blob_src.join("libc_shim.c"));
        b.compile("taclebench_native_shim");
    }

    // Which bench? Exactly one feature must be enabled.
    let bench = pick_bench();
    eprintln!("native_bench: building feature bench_{}", bench);

    match bench.as_str() {
        "fib" => compile_one("fib", &[bare.join("app/fibonacci.c")],
                              &[bare.join("inc")], &[]),

        "bsort" => compile_one("bsort", &[kernel.join("bsort/bsort.c")], &[], &[]),
        "countnegative" => compile_one("countnegative",
            &[kernel.join("countnegative/countnegative.c")], &[], &[]),
        "crc" => compile_one("crc", &[kernel.join("crc/crc.c")], &[], &[]),
        "md5" => compile_one("md5", &[kernel.join("md5/md5.c")], &[], &[]),
        "insertsort" => compile_one("insertsort",
            &[kernel.join("insertsort/insertsort.c")], &[], &[]),

        "ndes" => compile_one("ndes", &[seq.join("ndes/ndes.c")], &[], &[]),
        "statemate" => compile_one("statemate",
            &[seq.join("statemate/statemate.c")], &[], &[]),
        "petrinet" => compile_one("petrinet",
            &[seq.join("petrinet/petrinet.c")], &[], &[]),
        "adpcm_dec" => compile_one("adpcm_dec",
            &[seq.join("adpcm_dec/adpcm_dec.c")], &[], &[]),

        "anagram" => compile_one("anagram",
            &[
                seq.join("anagram/anagram.c"),
                seq.join("anagram/anagram_stdlib.c"),
                blob_src.join("anagram_input_small.c"),
            ],
            &[seq.join("anagram")],
            &[("anagram_DICTWORDS", "200"), ("ANAGRAM_HEAP_SIZE", "4000")],
        ),
        "cjpeg_wrbmp" => compile_one("cjpeg_wrbmp",
            &[
                seq.join("cjpeg_wrbmp/cjpeg_wrbmp.c"),
                seq.join("cjpeg_wrbmp/input.c"),
            ],
            &[seq.join("cjpeg_wrbmp")],
            &[],
        ),
        "dijkstra" => {
            // dijkstra needs `-include dijkstra_small_input.h` before
            // each .c — defines INPUT_H (skips upstream input.h) and
            // sets NUM_NODES=64, plus a custom QUEUE_SIZE.
            let small_input_h = blob_src.join("dijkstra_small_input.h");
            let mut b = base_build();
            b.define("main", "dijkstra_unused_main")
                .define("QUEUE_SIZE", "640")
                .include(seq.join("dijkstra"))
                .flag("-include")
                .flag(small_input_h.to_str().expect("ascii path"))
                .file(seq.join("dijkstra/dijkstra.c"))
                .file(blob_src.join("dijkstra_input_small.c"));
            b.compile("taclebench_native_dijkstra");
        }
        other => panic!("Unknown bench feature: bench_{other}"),
    }
}

fn pick_bench() -> String {
    let mut found: Vec<&str> = Vec::new();
    for name in ["fib", "bsort", "countnegative", "crc", "md5", "insertsort",
                 "ndes", "statemate", "petrinet", "adpcm_dec",
                 "anagram", "cjpeg_wrbmp", "dijkstra"] {
        let var = format!("CARGO_FEATURE_BENCH_{}", name.to_uppercase());
        if std::env::var(&var).is_ok() {
            found.push(name);
        }
    }
    match found.len() {
        0 => panic!("native_bench: no bench_<name> feature enabled. Pass --features=bench_fib (or another)."),
        1 => found[0].to_string(),
        _ => panic!("native_bench: multiple bench features enabled ({:?}). Pick exactly one.", found),
    }
}

fn compile_one(
    name: &str,
    files: &[PathBuf],
    includes: &[PathBuf],
    defines: &[(&str, &str)],
) {
    let mut b = base_build();
    // Suppress the bench's top-level `main` wrapper by renaming it
    // — we call the `_init/_main/_return` triplet directly from Rust.
    b.define("main", format!("{name}_unused_main").as_str());
    for i in includes {
        b.include(i);
    }
    for (k, v) in defines {
        b.define(k, *v);
    }
    for f in files {
        b.file(f);
    }
    b.compile(&format!("taclebench_native_{name}"));
}

fn base_build() -> cc::Build {
    let mut b = cc::Build::new();
    b.flag("-O0")
        .flag("-march=armv8-m.main")
        .flag("-mthumb")
        .flag("-ffunction-sections")
        .flag("-fdata-sections")
        .flag("-fno-builtin")
        .flag("-nostdinc")
        .flag("-nostdlib")
        .flag("-Wno-builtin-declaration-mismatch")
        .warnings(false);
    b
}
