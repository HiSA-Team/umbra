use super::*;

// Deterministic toy multi-part MAC (length-framed FNV-1a) — tests the FRAMING and
// the root's binding properties, NOT a specific crypto vector (the real HMAC-SHA256
// is the HW engine, KAT'd separately).
fn mock_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    fn absorb(h: &mut u64, bytes: &[u8]) {
        for &b in bytes { *h = (*h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3); }
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    absorb(&mut h, &(key.len() as u32).to_le_bytes());
    absorb(&mut h, key);
    for p in parts { absorb(&mut h, &(p.len() as u32).to_le_bytes()); absorb(&mut h, p); }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 { h = h.wrapping_mul(0x0000_0100_0000_01b3) ^ (i as u64); out[i..i+8].copy_from_slice(&h.to_le_bytes()); i += 8; }
    out
}

fn digs(seed: u8) -> [[u8; 32]; MAX_STATE_SECTORS] {
    let mut d = [[0u8; 32]; MAX_STATE_SECTORS];
    let mut i = 0;
    while i < MAX_STATE_SECTORS { d[i] = [seed.wrapping_add(i as u8); 32]; i += 1; }
    d
}

#[test]
fn root_is_deterministic() {
    let k = [0x11u8; 32]; let d = digs(1);
    assert_eq!(compute_root(&k, 7, 5, &d, mock_hmac), compute_root(&k, 7, 5, &d, mock_hmac));
}

#[test]
fn generation_binds() {
    // same content, different generation → different root (blocks replay-at-wrong-gen)
    let k = [0x11u8; 32]; let d = digs(1);
    assert_ne!(compute_root(&k, 7, 5, &d, mock_hmac), compute_root(&k, 7, 6, &d, mock_hmac));
}

#[test]
fn enclave_id_binds() {
    let k = [0x11u8; 32]; let d = digs(1);
    assert_ne!(compute_root(&k, 7, 5, &d, mock_hmac), compute_root(&k, 8, 5, &d, mock_hmac));
}

#[test]
fn any_sector_change_changes_root() {
    let k = [0x11u8; 32]; let mut d = digs(1);
    let base = compute_root(&k, 7, 5, &d, mock_hmac);
    d[9][0] ^= 0xFF;
    assert_ne!(base, compute_root(&k, 7, 5, &d, mock_hmac));
}

#[test]
fn discriminator_old_coherent_checkpoint_is_rejected() {
    // THE key test: an attacker presents the ENTIRE previous coherent checkpoint
    // (old digests) but the anchor is at the new generation with the new root.
    // Recomputing the root over the OLD flash digests at the anchor's generation
    // yields a DIFFERENT root than the anchor's → root_matches == false → reject.
    // A version-floor design would ACCEPT this stale state; the root rejects it.
    let k = [0x11u8; 32];
    let new_digests = digs(2);
    let old_digests = digs(1); // fully coherent old checkpoint
    let anchor_root = compute_root(&k, 7, 5, &new_digests, mock_hmac); // committed at gen 5
    // attacker rolls flash back to old_digests; restore recomputes at gen 5:
    let recomputed = compute_root(&k, 7, 5, &old_digests, mock_hmac);
    assert!(!root_matches(&anchor_root, &recomputed), "stale replay must be rejected");
    // sanity: the genuine current state matches
    let genuine = compute_root(&k, 7, 5, &new_digests, mock_hmac);
    assert!(root_matches(&anchor_root, &genuine));
}

#[test]
fn root_matches_is_constant_time_and_correct() {
    let a = [0xAAu8; 16];
    let mut b = a;
    assert!(root_matches(&a, &b));
    b[15] ^= 0x01;
    assert!(!root_matches(&a, &b));
    b = a; b[0] ^= 0x80;
    assert!(!root_matches(&a, &b));
}
