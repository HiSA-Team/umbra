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

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

const PLATFORMS: [&str; 3] = ["l552", "l562", "n657"];

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
        Cmd::Build { platform } => build(&platform),
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
        _ => unreachable!("clap restricts the value to PLATFORMS"),
    }
}

/// L562 shares the L552 host tree (MCU=stm32l552 for both). Binary path
/// is determined by MCU (`host/<mcu>/bare_metal/...`), not MCU_VARIANT.
fn bare_metal_bin_rel(platform: &str) -> &'static str {
    match platform {
        "l552" | "l562" => "host/stm32l552/bare_metal/bin/bare_metal.bin",
        "n657" => "host/stm32n657/bare_metal/bin/bare_metal.bin",
        _ => unreachable!("clap restricts the value to PLATFORMS"),
    }
}

fn build(platform: &str) -> Result<()> {
    // rebuild_all.sh + settings.sh read the platform from the MCU_VARIANT
    // env var (defaulting to stm32n657 when unset). Argv is ignored. Set
    // the env var explicitly so `cargo xtask build <plat>` actually builds
    // the requested platform regardless of the user's shell environment.
    let status = Command::new("./rebuild_all.sh")
        .current_dir(repo_root())
        .env("MCU_VARIANT", mcu_variant(platform))
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
    build(platform)?;

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
    let (script, script_label) = match platform {
        "l552" | "l562" => ("./debug.sh", "debug.sh"),
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
        "tools/master_key.bin",
    ];
    let _ = Command::new("git")
        .current_dir(&root)
        .args(["checkout", "HEAD", "--"])
        .args(mk_files)
        .status();
    eprintln!("[xtask flash] master_key residue auto-reverted (NEVER_DO rule 10).");
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
