// Pass the host linker script as an absolute path (centralized in the bin
// crate, same pattern as the firmware boot crates).
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let link_script = manifest.join("linker").join("host.ld");
    println!("cargo:rustc-link-arg=-T{}", link_script.display());
    println!("cargo:rerun-if-changed=linker/host.ld");
}
