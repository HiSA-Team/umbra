fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let out_dir = std::env::var("OUT_DIR").unwrap();

    if target.contains("thumbv") || target.contains("arm") {
        // N657-specific startup (vector table with correct alias offsets,
        // handlers, _umb_start). Uses platform-specific file instead of the
        // shared startup.s because the vector table entries differ:
        //   L5:   _umb_Reset_Handler+0x04000001 (flash NS→Secure alias)
        //   N657: _umb_Reset_Handler+1          (already at Secure alias)
        let startup_obj = format!("{}/startup.o", out_dir);
        assemble("asm/arm/startup_n657.s", &startup_obj);
        println!("cargo:rustc-link-arg={}", startup_obj);
        println!("cargo:rerun-if-changed=asm/arm/startup_n657.s");

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

    }
}

fn assemble(src: &str, obj: &str) {
    // Use cortex-m33 as the assembler CPU target. The Cortex-M55 is a strict
    // superset of M33 for Thumb-2 + TrustZone instructions. Using cortex-m33
    // here is safe because our assembly does not contain any M55-specific
    // instructions (MVE/Helium). Switch to cortex-m55 when the toolchain
    // supports it and Helium context save is added.
    let status = std::process::Command::new("arm-none-eabi-as")
        .args(&["-mcpu=cortex-m33", "-mthumb", "-o", obj, src])
        .status()
        .expect("Failed to run arm-none-eabi-as");
    assert!(status.success(), "Assembly of {} failed", src);
}
