use std::path::PathBuf;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let out_dir = std::env::var("OUT_DIR").unwrap();
    // CARGO_MANIFEST_DIR is the boot crate dir; build.rs runs with this as
    // its CWD. Linker scripts go through rustc as `-T<absolute path>` so
    // the linker's CWD (workspace root post-earlier absorption) doesn't
    // matter; relative paths broke after workspace absorption.
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // boot/ → src/hardware/platform/stm32l552/boot/ →../../../../../ = workspace root
    let workspace_root = manifest_dir
        .join("../../../../..")
        .canonicalize()
        .expect("Failed to canonicalize workspace root from CARGO_MANIFEST_DIR");

    if target.contains("thumbv") || target.contains("arm") {
        // Startup assembly (vector table, handlers, _umb_start)
        let startup_obj = format!("{}/startup.o", out_dir);
        assemble("../../../architecture/arm/asm/startup.s", &startup_obj);
        println!("cargo:rustc-link-arg={}", startup_obj);
        println!("cargo:rerun-if-changed=../../../architecture/arm/asm/startup.s");

        // NSC veneers (SG entry points for NS→S calls)
        let nsc_obj = format!("{}/nsc_veneers.o", out_dir);
        assemble("../../../../kernel/asm/arm/nsc_veneers.s", &nsc_obj);
        println!("cargo:rustc-link-arg={}", nsc_obj);
        println!("cargo:rerun-if-changed=../../../../kernel/asm/arm/nsc_veneers.s");

        // Trampoline (S→NS world transition)
        let tramp_obj = format!("{}/trampoline.o", out_dir);
        assemble("asm/arm/trampoline.s", &tramp_obj);
        println!("cargo:rustc-link-arg={}", tramp_obj);
        println!("cargo:rerun-if-changed=asm/arm/trampoline.s");

        // Linker scripts (previously in.cargo/config.toml with relative
        // paths; broke under workspace absorption).
        let linker_scripts = [
            workspace_root.join("host/stm32l552/bare_metal/linker/memory.ld"),
            workspace_root.join("linker/umbra.ld"),
            manifest_dir.join("../linker/platform.ld"),
        ];
        for script in &linker_scripts {
            let abs = script
                .canonicalize()
                .unwrap_or_else(|e| panic!("Linker script {} not found: {}", script.display(), e));
            println!("cargo:rustc-link-arg=-T{}", abs.display());
            println!("cargo:rerun-if-changed={}", abs.display());
        }
    }
}

fn assemble(src: &str, obj: &str) {
    let status = std::process::Command::new("arm-none-eabi-as")
        .args(["-mcpu=cortex-m33", "-mthumb", "-o", obj, src])
        .status()
        .expect("Failed to run arm-none-eabi-as");
    assert!(status.success(), "Assembly of {} failed", src);
}
