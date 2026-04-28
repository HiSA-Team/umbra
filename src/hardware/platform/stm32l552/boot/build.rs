fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let out_dir = std::env::var("OUT_DIR").unwrap();

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
    }
}

fn assemble(src: &str, obj: &str) {
    let status = std::process::Command::new("arm-none-eabi-as")
        .args(&["-mcpu=cortex-m33", "-mthumb", "-o", obj, src])
        .status()
        .expect("Failed to run arm-none-eabi-as");
    assert!(status.success(), "Assembly of {} failed", src);
}
