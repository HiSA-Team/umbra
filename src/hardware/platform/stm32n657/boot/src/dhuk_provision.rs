//! Issue #45 orchestrator: provision-if-absent + DHUK wrap/share of the
//! enc_key, so the AES key reaches CRYP over the SAES shared-key bus instead of
//! a CPU register write.
//!
//! Called from `init_kernel` AFTER `init_keys` (where the kernel's `enc_key`
//! has been derived). Fail-closed: if CRYP does not end up with a valid shared
//! key, the boot panics rather than continuing on a broken crypto path.
//!
//! Self-contained — it owns fresh `Hash`/`Saes`/`Cryp1`/`Bkpsram` accessors
//! (all at fixed MMIO bases; clocks already enabled by `AesHardware::new` /
//! `Hash::new` earlier in `init_kernel`), so it does not borrow the kernel's
//! crypto engine. See docs/superpowers/specs/2026-06-25-n657-dhuk-...-design.md.

use drivers::bkpsram::{self, Bkpsram, Slot, SLOT_MAGIC, WRAP_BLOB_LEN};
use drivers::cryp::Cryp1;
use drivers::hash::Hash;
use drivers::saes::Saes;

/// HMAC label for the rotated-key detection tag. Distinct from the enc/hmac
/// KDF labels so the tag can never collide with a real derived key.
const TAG_LABEL: &[u8] = b"umbra-dhuk-tag";

/// Wrap `enc_key` under DHUK (provision-if-absent into BKPSRAM), then decrypt
/// and share it to CRYP over the silicon bus. Panics fail-closed if CRYP's
/// KEYVALID is not set afterwards.
pub fn provision_and_share_enc_key(enc_key: &[u8; 16]) {
    bkpsram::init_backup_domain();

    // tag = HMAC(enc_key, "umbra-dhuk-tag")[:4] — detects a key rotated by a
    // rebuild so a stale BKPSRAM blob is re-provisioned.
    let mut mac = [0u8; 32];
    let mut hash = Hash::new();
    hash.hmac_sha256(enc_key, TAG_LABEL, &mut mac);
    let tag = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);

    let mut bk = Bkpsram::new();
    let mut saes = Saes::new();
    let slot = bk.read_slot();

    let blob: [u8; WRAP_BLOB_LEN] = if slot.magic == SLOT_MAGIC && slot.tag == tag {
        crate::raw_print::print_str("[UMBRASecureBoot] DHUK reused\n");
        slot.blob
    } else {
        crate::raw_print::print_str("[UMBRASecureBoot] DHUK provisioned\n");
        let b = saes.wrap_under_dhuk(enc_key);
        bk.write_slot(&Slot {
            magic: SLOT_MAGIC,
            tag,
            blob: b,
        });
        b
    };

    // Decrypt the blob under DHUK and broadcast the key to CRYP over the bus.
    saes.unwrap_and_share_to_cryp(&blob);

    // Fail-closed: CRYP must now hold a valid shared key.
    let mut cryp = Cryp1::new();
    cryp.configure_ecb_shared();
    if cryp.key_valid() {
        crate::raw_print::print_str("[UMBRASecureBoot] DHUK share OK (CRYP KEYVALID)\n");
    } else {
        crate::raw_print::print_str("[UMBRASecureBoot] DHUK share FAIL (no KEYVALID)\n");
        panic!("DHUK key share failed");
    }

    // On-chip state-continuity proof-slice (dev-only feature). Runs here because the
    // backup domain, the HASH clock and a stable device key are all up by now.
    #[cfg(feature = "state_continuity_probe")]
    state_continuity_probe(enc_key);

    #[cfg(feature = "xspi_write_probe")]
    xspi_write_probe();
}

/// Flash-continuity probe: the full checkpoint → reset → restore loop over PERSISTED
/// state — real double-buffered TAMP anchor AND real flash sectors. Boot 1 (cold
/// anchor) checkpoints two sectors to flash via the real `write_state_sector` and
/// commits the anchor; after a reset boot 2 recomputes the root over the persisted
/// flash + anchor and restores → Resume. Maps XSPI2 itself first (runs before
/// init_external_flash). Feature-gated — NEVER in a production image.
#[cfg(feature = "xspi_write_probe")]
fn xspi_write_probe() {
    use crate::raw_print::{print_hex, print_str};
    // XSPI2 is not mapped yet at this point in boot — bring it up (idempotent).
    let _ = crate::platform_impl::dma::init_external_flash();
    print_str("[FC] mm ready\n");
    // Stable probe key across boots: enc_key is ephemeral (DHUK-wrapped, changes per
    // boot), so it can't key a root that must be re-verified after a reset. The real
    // integration keys this with the device MASTER_KEY.
    const PROBE_KEY: [u8; 16] = [0x42u8; 16];
    let r = drivers::state_store::run_flash_continuity_probe(&PROBE_KEY, 0);
    if r.resumed {
        print_str("[FC] restore gen=");
        print_hex(r.gen);
        print_str(" Resume PASS sr=");
        print_hex(r.stored_root);
        print_str(" rr=");
        print_hex(r.recomp_root);
        print_str("\n");
    } else {
        print_str("[FC] checkpointed gen=");
        print_hex(r.gen);
        print_str(" (sr=");
        print_hex(r.stored_root);
        print_str(" rr=");
        print_hex(r.recomp_root);
        print_str(" rr2=");
        print_hex(r.recomp_root2);
        print_str(" s0=");
        print_hex(r.sec0_raw);
        print_str(") — press RST\n");
    }
}

/// On-chip proof-slice: run the state-continuity control loop on REAL TAMP + HASH
/// (RAM-backed sectors, no XSPI2 write) and report over UART. Feature-gated —
/// NEVER in a production image. Terse strings: the Secure boot text region is full,
/// so every `.rodata` byte counts (see the build note / ADR 010).
#[cfg(feature = "state_continuity_probe")]
fn state_continuity_probe(key: &[u8]) {
    use crate::raw_print::{print_hex, print_str};
    let r = drivers::state_store::run_state_continuity_probe(key, 0);
    match r.anchor_survived_gen {
        Some(g) => {
            print_str("[SP] survived reset g=");
            print_hex(g);
            print_str("\n");
        }
        None => print_str("[SP] cold anchor\n"),
    }
    print_str("[SP] g=");
    print_hex(r.committed_gen);
    print_str(if r.resumed_ok { " resume=OK" } else { " resume=FAIL" });
    print_str(if r.tamper_rejected { " tamper=REJECT\n" } else { " tamper=FAIL\n" });
}
