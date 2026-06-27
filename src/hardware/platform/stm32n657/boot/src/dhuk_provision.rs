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
}
