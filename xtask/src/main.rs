//! `cargo xtask` — build / flash / test orchestration for Umbra.
//! Replaces direct invocations of `rebuild_all.sh`, `debug.sh`, and the
//! root `Makefile`. Each subcommand below wraps an existing script during
//!; the native-Rust pipeline (no shell wrapper) is a /3
//! target once the workspace covers every embedded crate.
//! Run from the repo root: `cargo xtask <subcommand>`.
//! ## Platforms
//! - `l552` → STM32L552 (no HW AES, AesEmulated path, MCU_VARIANT=stm32l552)
//! - `l562` → STM32L562 (HW AES + OTFDEC, same boot crate as L552 with the
//!   `stm32l562` Cargo feature on, MCU_VARIANT=stm32l562)
//! - `n657` → STM32N657 (Cortex-M55, FSBL flow, MCU_VARIANT=stm32n657)
//! - `riscv32` → RISC-V RV32 on QEMU virt (M/S/U + PMP/SPMP, MCU_VARIANT=riscv32).
//!   `flash` launches the SPMP-patched QEMU instead of an ST-LINK flash flow.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

const PLATFORMS: [&str; 4] = ["l552", "l562", "n657", "riscv32"];

#[derive(Parser)]
#[command(name = "xtask", about = "Umbra build / flash / test orchestration")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the Secure-boot firmware for a given platform.
    Build {
        #[arg(value_parser = PLATFORMS)]
        platform: String,
    },
    /// Flash + attach GDB. Reverts master_key residue after the session.
    Flash {
        #[arg(value_parser = PLATFORMS)]
        platform: String,
    },
    /// Run host-side tests (cargo-llvm-cov when available, plain test otherwise).
    Test {
        #[arg(long)]
        host: bool,
    },
    /// Print the bare-metal binary size, warn if above the soft cap.
    CheckBinarySize {
        #[arg(value_parser = PLATFORMS)]
        platform: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build { platform } => build(&platform, false),
        Cmd::Flash { platform } => flash(&platform),
        Cmd::Test { host } => test(host),
        Cmd::CheckBinarySize { platform } => check_binary_size(&platform),
    }
}

fn repo_root() -> PathBuf {
    // xtask binary lives at <repo>/target/<profile>/xtask, but `cargo xtask`
    // sets CARGO_MANIFEST_DIR to the xtask crate dir. The repo root is its parent.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate has a parent directory")
        .to_path_buf()
}

/// Map a user-facing platform name to the `MCU_VARIANT` env var that
/// `settings.sh` consumes. The shell-side maps L552+L562 onto the same
/// `MCU=stm32l552` value (shared boot crate + host tree), but the
/// distinction is preserved in MCU_VARIANT so feature flags (`--features
/// stm32l562`) and EXTLOAD_STLDR get set correctly.
fn mcu_variant(platform: &str) -> &'static str {
    match platform {
        "l552" => "stm32l552",
        "l562" => "stm32l562",
        "n657" => "stm32n657",
        "riscv32" => "riscv32",
        _ => unreachable!("clap restricts the value to PLATFORMS"),
    }
}

/// L562 shares the L552 host tree (MCU=stm32l552 for both). Binary path
/// is determined by MCU (`host/<mcu>/bare_metal/...`), not MCU_VARIANT.
fn bare_metal_bin_rel(platform: &str) -> &'static str {
    match platform {
        "l552" | "l562" => "host/stm32l552/bare_metal/bin/bare_metal.bin",
        "n657" => "host/stm32n657/bare_metal/bin/bare_metal.bin",
        // The RISC-V host is a Cargo crate; its artifact is the ELF (no .bin).
        "riscv32" => {
            "host/riscv32/bare_metal/target/riscv32imac-unknown-none-elf/release/bare_metal"
        }
        _ => unreachable!("clap restricts the value to PLATFORMS"),
    }
}

fn build(platform: &str, dev_debug: bool) -> Result<()> {
    // rebuild_all.sh + settings.sh read the platform from the MCU_VARIANT
    // env var (defaulting to stm32n657 when unset). Argv is ignored. Set
    // the env var explicitly so `cargo xtask build <plat>` actually builds
    // the requested platform regardless of the user's shell environment.
    //
    // `dev_debug` (true only on the n657 flash path) sets UMBRA_DEV_DEBUG=1,
    // which settings.sh turns into `--features dev_debug` for the boot crate —
    // opening the FSBL debug access port. Plain `cargo xtask build` passes
    // false, keeping it out of the artefact.
    let status = Command::new("./rebuild_all.sh")
        .current_dir(repo_root())
        .env("MCU_VARIANT", mcu_variant(platform))
        .env("UMBRA_DEV_DEBUG", if dev_debug { "1" } else { "0" })
        .arg(platform)
        .status()
        .context("Failed to spawn ./rebuild_all.sh — is it executable from repo root?")?;
    if !status.success() {
        anyhow::bail!(
            "rebuild_all.sh {} failed (exit {:?})",
            platform,
            status.code()
        );
    }
    Ok(())
}

fn flash(platform: &str) -> Result<()> {
    // Build-then-flash, cargo-run semantics. rebuild_all.sh rotates the
    // master_key on every invocation and re-signs every artefact that
    // embeds it (boot ELF, bundled fib in the host ELF, taclebench blobs);
    // flashing without rebuilding leaves the on-chip secure boot using a
    // newer key than the host's bundled fib HMAC, producing
    // `chained-measurement FAIL` at runtime. Always build first to keep
    // the master_key chain end-to-end consistent.
    //
    // dev_debug is enabled on the n657 flash path so the flashed FSBL opens
    // its debug access port (the `dev_debug` feature exists only on n657).
    build(platform, platform == "n657")?;

    // Absorb SIGINT in xtask so the user's Ctrl+C reaches the GDB child
    // (which interrupts its inferior — standard GDB UX) WITHOUT also
    // killing xtask itself. Without this, Ctrl+C terminates xtask first;
    // the shell takes over the foreground TTY, subsequent Ctrl+Cs never
    // reach debug.sh's openocd cleanup trap, and openocd is left as an
    // orphan holding the ST-LINK probe (user-reported on 2026-05-31).
    // The closure intentionally does nothing — child processes still
    // receive their own copy of SIGINT via the foreground process group.
    let _ = ctrlc::set_handler(|| {
        // No-op; let GDB and debug.sh's trap handle the signal.
    });

    let root = repo_root();
    // Platform-specific flash flow:
    // - l552/l562 → debug.sh (STM32_Programmer_CLI wipe + openocd + GDB load).
    // The L5 boot ELF lives in internal flash and the openocd+GDB flow is
    // the established path (RIF/RIFSC isn't a factor on L5).
    // - n657 → tools/flash_n657.sh (STM32CubeProgrammer dev-boot flow
    // via XSPI2 external flash). N6 uses Boot ROM → FSBL chain and the
    // dev-boot mode (JP2=2-3) avoids the GDB register-access concerns
    // entirely. After flash, user switches JP2 to 1-2 and resets to
    // cold-boot the FSBL from XSPI2.
    // - riscv32 → debug.sh launches the SPMP-patched QEMU (no ST-LINK flash);
    // the monitor ELF is loaded via -kernel and the host image via -device
    // loader. "Flash" here means "deploy + run on the emulator".
    let (script, script_label) = match platform {
        "l552" | "l562" | "riscv32" => ("./debug.sh", "debug.sh"),
        "n657" => ("./tools/flash_n657.sh", "tools/flash_n657.sh"),
        _ => unreachable!("clap restricts the value"),
    };

    let mut cmd = Command::new(script);
    cmd.current_dir(&root)
        .env("MCU_VARIANT", mcu_variant(platform))
        // Explicit BOOT_CRATE_NAME override defends against a leftover
        // value from a prior `source./settings.sh` in the user's shell
        // (e.g. tested L552 first then ran `cargo xtask flash n657` from
        // the same shell). Without this, flash_n657.sh inherits the
        // stale L552 binary name and writes umbra-l552-boot-trusted.bin
        // to N657's XSPI2. See settings.sh §mcu_selection for the per-MCU
        // mapping. Mirrors what `source./settings.sh` would compute.
        .env(
            "BOOT_CRATE_NAME",
            match platform {
                "l552" | "l562" => "umbra-l552-boot",
                "n657" => "umbra-n657-boot",
                "riscv32" => "umbra-riscv32-boot",
                _ => unreachable!("clap restricts the value"),
            },
        );
    // debug.sh consumes the platform argv as a sanity arg; flash_n657.sh
    // doesn't — it reads MCU_VARIANT directly. Pass argv only where it's used.
    if platform != "n657" {
        cmd.arg(platform);
    }
    let status = cmd
        .status()
        .with_context(|| format!("Failed to spawn {}", script_label))?;
    if !status.success() {
        anyhow::bail!("{} failed (exit {:?})", script_label, status.code());
    }
    // Post-flash: revert master_key residue. Recurring pattern documented
    // post-mortem; enforces NEVER_DO rule 10 mechanically.
    let mk_files = [
        "src/hardware/platform/stm32l552/boot/src/master_key.rs",
        "src/hardware/platform/stm32n657/boot/src/master_key.rs",
        "src/hardware/platform/riscv32/boot/src/master_key.rs",
        "tools/master_key.bin",
    ];
    let _ = Command::new("git")
        .current_dir(&root)
        .args(["checkout", "HEAD", "--"])
        .args(mk_files)
        .status();
    eprintln!("[xtask flash] master_key residue auto-reverted (NEVER_DO rule 10).");

    // n657: after flashing, let the user move the BOOT1 jumper, then launch the
    // attach-mode openocd + gdb session that resets the micro and breaks at
    // init_kernel (tools/n657_debug.gdb does the `monitor reset halt`).
    if platform == "n657" {
        println!();
        println!(">>> Set JP2 (BOOT1) to position 1-2 (Flash Boot), press the RESET button,");
        print!(">>> then press Enter to start GDB at init_kernel... ");
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        let mut _line = String::new();
        let _ = std::io::stdin().read_line(&mut _line);

        // Kill any stale openocd holding the ST-LINK / :3333 from a previous
        // manual session — otherwise the new openocd can't bind and gdb
        // attaches to the confused old one ("Remote replied unexpectedly to
        // 'vMustReplyEmpty'"). Give it a moment to release the USB probe + port.
        let _ = Command::new("pkill").args(["-x", "openocd"]).status();
        std::thread::sleep(std::time::Duration::from_millis(800));

        // openocd in the background (attach cfg = no reset on connect); its
        // chatter goes to a log so the gdb console stays clean.
        let oc_log = std::fs::File::create("/tmp/openocd_n657.log")
            .context("Failed to create /tmp/openocd_n657.log")?;
        let oc_err = oc_log
            .try_clone()
            .context("Failed to clone openocd log fd")?;
        // process_group(0): put openocd in its OWN process group so a terminal
        // Ctrl+C (delivered to xtask+gdb's foreground group) does NOT reach it.
        // Otherwise SIGINT shuts openocd down ("shutdown command invoked" ->
        // "Connection reset by peer") instead of letting gdb interrupt the
        // inferior — the user expects Ctrl+C to HALT the running NS-world loop.
        use std::os::unix::process::CommandExt as _;
        let mut openocd = Command::new("openocd")
            .current_dir(&root)
            .args(["-f", "openocd_scripts/stm32n6x_attach.cfg"])
            .stdout(oc_log)
            .stderr(oc_err)
            .process_group(0)
            .spawn()
            .context("Failed to spawn openocd — is it on PATH?")?;

        // Wait until openocd actually accepts connections (telnet :4444, a benign
        // readiness proxy for the gdb :3333 it opens at the same time), instead
        // of a blind sleep that can race on a slow/contended probe.
        let mut ready = false;
        for _ in 0..30 {
            if std::net::TcpStream::connect("127.0.0.1:4444").is_ok() {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        if !ready {
            let _ = openocd.kill();
            let _ = openocd.wait();
            anyhow::bail!("openocd never opened its ports — see /tmp/openocd_n657.log");
        }
        println!("[xtask flash] openocd attached (log: /tmp/openocd_n657.log)");

        // NS host symbols: pick the ELF from HOST_APP (default bare_metal) so `bt` resolves in
        // the host world — e.g. two_enclaves' main/run_overlay — instead of raw `0x2400xxxx in
        // ?? ()`. Injected as a TRAILING -ex so it runs after n657_debug.gdb's `file <boot>`
        // (which would otherwise discard an earlier add-symbol-file). The .text VMA is 0x24000100
        // for every N657 host (shared linker layout). `set confirm off` in the script suppresses
        // the add-symbol-file prompt.
        let host_app = std::env::var("HOST_APP").unwrap_or_else(|_| "bare_metal".to_string());
        let host_syms = format!(
            "add-symbol-file host/stm32n657/{host_app}/bin/{host_app}.elf 0x24000100"
        );

        // Interactive gdb; -nx skips the user's Python-laden ~/.gdbinit.
        let gdb_res = Command::new("arm-none-eabi-gdb")
            .current_dir(&root)
            .args(["-nx", "-x", "tools/n657_debug.gdb"])
            .arg("-ex")
            .arg(&host_syms)
            .status();

        // gdb exited -> tear down openocd so the ST-LINK probe is freed.
        let _ = openocd.kill();
        let _ = openocd.wait();
        gdb_res.context("Failed to spawn arm-none-eabi-gdb — is it on PATH?")?;
    }

    Ok(())
}

fn test(host: bool) -> Result<()> {
    if !host {
        anyhow::bail!("Embedded test runner not yet implemented — pass --host");
    }
    let root = repo_root();
    // Prefer cargo-llvm-cov when present; fall back to plain `cargo test`.
    let llvm_cov_available = Command::new("cargo")
        .args(["llvm-cov", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let status = if llvm_cov_available {
        Command::new("cargo")
            .current_dir(&root)
            .args([
                "llvm-cov",
                "--workspace",
                "--lcov",
                "--output-path",
                "lcov.info",
                "--ignore-filename-regex",
                "(host/|lib/|tools/)",
            ])
            .status()
            .context("cargo-llvm-cov invocation failed")?
    } else {
        eprintln!(
            "[xtask test] cargo-llvm-cov not installed; running plain `cargo test --workspace`."
        );
        Command::new("cargo")
            .current_dir(&root)
            .args(["test", "--workspace"])
            .status()
            .context("cargo test invocation failed")?
    };
    if !status.success() {
        anyhow::bail!("host test run failed");
    }
    eprintln!("[xtask test] host suite passed.");
    Ok(())
}

fn check_binary_size(platform: &str) -> Result<()> {
    let bin_path = repo_root().join(bare_metal_bin_rel(platform));
    let meta = std::fs::metadata(&bin_path).with_context(|| {
        format!(
            "Binary not found at {} — run `cargo xtask build {}` first",
            bin_path.display(),
            platform
        )
    })?;
    let size_kb = meta.len() / 1024;
    eprintln!(
        "[xtask check-binary-size] {} = {} KB",
        bin_path.display(),
        size_kb
    );
    // Soft regression guard. Production bin currently sits at ~50-70 KB
    // depending on feature set; 80 KB is a generous ceiling that CI will
    // tighten once lands the workspace-wide build path.
    if size_kb > 80 {
        eprintln!("WARNING: binary size {} KB exceeds soft cap 80 KB", size_kb);
    }
    Ok(())
}
