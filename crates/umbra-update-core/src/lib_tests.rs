extern crate std;
use super::*;
use std::vec::Vec;

// Rust-vs-vm_compute differential corpus dumper (gated by UMBRA_DUMP_DIFFERENTIAL).
#[path = "differential_dump.rs"]
mod differential_dump;

// Mock HMAC: deterministic fold over key+preimage. Not cryptographic — just a
// stable function so parse/round-trip tests are meaningful.
struct MockHmac;
impl PkgHmac for MockHmac {
    fn hmac_pkg(&self, key: &[u8], pre: &[u8; PKG_PREIMAGE_LEN]) -> [u8; 32] {
        let mut acc = [0u8; 32];
        let mut n = 0usize;
        for &b in key {
            acc[n % 32] = acc[n % 32].wrapping_add(b).wrapping_add(1);
            n += 1;
        }
        for &b in pre.iter() {
            acc[n % 32] = acc[n % 32].wrapping_add(b).wrapping_add(2);
            n += 1;
        }
        acc
    }
}

fn make_pkg(nonce: [u8; 16], author: u32, version: u32, blob: &[u8], key: &[u8]) -> Vec<u8> {
    let mut header = [0u8; HDR_LEN];
    header.copy_from_slice(&blob[0..HDR_LEN]);
    let tag = compute_pkg_tag(&nonce, author, version, blob.len() as u32, &header, &MockHmac, key);
    let mut pkg = Vec::new();
    pkg.extend_from_slice(&UPDATE_MAGIC.to_le_bytes());
    pkg.extend_from_slice(&nonce);
    pkg.extend_from_slice(&author.to_le_bytes());
    pkg.extend_from_slice(&version.to_le_bytes());
    pkg.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    pkg.extend_from_slice(blob);
    pkg.extend_from_slice(&tag);
    pkg
}

fn dummy_blob() -> Vec<u8> {
    let mut b = std::vec![0u8; 336]; // 48-byte header + 288-byte block
    for i in 0..48 {
        b[i] = i as u8;
    }
    b
}

#[test]
fn accepts_matching_nonce_and_tag() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let pkg = make_pkg(nonce, 1, 3, &blob, &key);
    let r = parse_and_verify(&pkg, &nonce, &MockHmac, &key);
    assert!(matches!(r, Ok(ref u) if u.version == 3 && u.author_id == 1 && u.blob == &blob[..]));
}

#[test]
fn rejects_wrong_nonce() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let pkg = make_pkg(nonce, 1, 3, &blob, &key);
    let mut expected = nonce;
    expected[0] ^= 1;
    assert_eq!(parse_and_verify(&pkg, &expected, &MockHmac, &key).err(), Some(UpdateError::NonceMismatch));
}

#[test]
fn rejects_tampered_tag() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let mut pkg = make_pkg(nonce, 1, 3, &blob, &key);
    let last = pkg.len() - 1;
    pkg[last] ^= 0xFF;
    assert_eq!(parse_and_verify(&pkg, &nonce, &MockHmac, &key).err(), Some(UpdateError::TagInvalid));
}

#[test]
fn rejects_truncated_package() {
    assert_eq!(parse_and_verify(&[0u8; 8], &[0x22; 16], &MockHmac, &[0x5A; 32]).err(), Some(UpdateError::Malformed));
}

/// v2 regression: the tag now covers the WHOLE 48-byte header, so flipping a
/// byte the v1 preimage left out (trust_level at blob[4], efbc_size at
/// blob[6,8), ess_blocks at blob[8,10), reloc_count at blob[14,16)) after
/// signing must be TagInvalid. Under v1 all four flips were silently accepted.
#[test]
fn rejects_post_signing_flip_of_formerly_unauthenticated_header_bytes() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let pkg = make_pkg(nonce, 1, 3, &blob, &key);
    for &blob_off in &[4usize, 6, 8, 14] {
        let mut tampered = pkg.clone();
        tampered[32 + blob_off] ^= 0x01; // blob starts at pkg[32]
        assert_eq!(
            parse_and_verify(&tampered, &nonce, &MockHmac, &key).err(),
            Some(UpdateError::TagInvalid),
            "header byte blob[{blob_off}] must be tag-covered"
        );
    }
}

// P3 witness: a near-usize::MAX blob_len must be Malformed with NO arithmetic panic.
#[test]
fn huge_blob_len_is_malformed_not_panic() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let mut pkg = make_pkg(nonce, 0x0A0B0C0D, 0x1112_1314, &blob, &key);
    pkg[28..32].copy_from_slice(&0xFFFF_FFC0_u32.to_le_bytes());
    assert_eq!(parse_and_verify(&pkg, &nonce, &MockHmac, &key).err(), Some(UpdateError::Malformed));
}

// Boundary: a blob of exactly MIN_BLOB (48 bytes = header only, no block) must be
// accepted — the header-copy `blob[0..48]` is in-bounds at the minimum size. Guards
// the exact-48 edge of the widened copy window (v1 copied blob[16..48], which was
// also 48-safe; v2 copies blob[0..48], same boundary, pinned here explicitly).
#[test]
fn accepts_exactly_min_blob() {
    let key = [0x5A; 32];
    let nonce = [0x11; 16];
    let mut blob = std::vec![0u8; 48];
    for i in 0..48 {
        blob[i] = (0x80 + i) as u8;
    }
    let pkg = make_pkg(nonce, 7, 9, &blob, &key);
    let r = parse_and_verify(&pkg, &nonce, &MockHmac, &key);
    assert!(matches!(r, Ok(ref u) if u.version == 9 && u.blob == &blob[..]));
}

#[test]
fn selects_higher_authenticated_version() {
    assert_eq!(select_active_slot(Some(2), Some(5)), Some(1));
    assert_eq!(select_active_slot(Some(5), Some(2)), Some(0));
    assert_eq!(select_active_slot(Some(3), Some(3)), Some(0));
    assert_eq!(select_active_slot(Some(2), None), Some(0));
    assert_eq!(select_active_slot(None, Some(4)), Some(1));
    assert_eq!(select_active_slot(None, None), None);
}

// ---------------------------------------------------------------------------
// Producer/consumer parity under a REAL HMAC-SHA-256
// ---------------------------------------------------------------------------
//
// Every test above runs on `MockHmac`, so they pin the parse/gate behaviour but
// say nothing about the bytes the device and `tools/attest_update.py` actually
// exchange. Parity used to rest on two things: the preimage-ORDER test
// (`kernel::key_storage_server::enclave_update_tests::pkg_tag_preimage_order_matches_python`)
// and the belief that both sides call the same standard primitive. This closes
// the gap end to end: the same fixed vectors, the same real HMAC-SHA-256, the
// same 32-byte tag Python asserts.
//
// No runtime dependency and no new dev-dependency — SHA-256 and HMAC are ~70
// lines of 32-bit arithmetic, live only in `#[cfg(test)]`, and are themselves
// pinned by published vectors (`sha256_and_hmac_match_published_vectors`) so a
// broken primitive cannot make the golden tag agree by accident.

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// FIPS 180-4 SHA-256, byte-oriented, no dependencies.
#[allow(clippy::needless_range_loop)]
fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bitlen = (msg.len() as u64).wrapping_mul(8);
    let mut m: Vec<u8> = Vec::from(msg);
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in m.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let a = w[i - 15];
            let b = w[i - 2];
            let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
            let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

/// RFC 2104 / FIPS 198-1 HMAC over SHA-256 (block size 64).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    let mut outer = Vec::with_capacity(64 + 32);
    for &b in k.iter() {
        inner.push(b ^ 0x36);
        outer.push(b ^ 0x5c);
    }
    inner.extend_from_slice(msg);
    outer.extend_from_slice(&sha256(&inner));
    sha256(&outer)
}

fn hex(b: &[u8]) -> std::string::String {
    use core::fmt::Write;
    let mut s = std::string::String::new();
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// The primitive above, against published vectors — so the golden tag below
/// tests parity and not merely self-consistency.
#[test]
fn sha256_and_hmac_match_published_vectors() {
    // FIPS 180-4 examples (one-block, empty, and a multi-block message).
    assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(
        hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // RFC 4231 HMAC-SHA-256 test cases 1, 2 and 6 (the last exercises the
    // key-longer-than-block-size branch).
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(
        hex(&hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

struct RealHmac;
impl PkgHmac for RealHmac {
    fn hmac_pkg(&self, key: &[u8], pre: &[u8; PKG_PREIMAGE_LEN]) -> [u8; 32] {
        hmac_sha256(key, pre)
    }
}

/// **The KAT.** `compute_pkg_tag` under a real HMAC-SHA-256, on the vectors
/// `tools/test_attestation_guard.py::test_pkg_tag_preimage` uses, must produce
/// the tag that script asserts. Fails if the label, the field order, any field
/// width/endianness, or the header window changes on either side — i.e. it is
/// the executable statement of Rust↔Python producer/consumer parity, which
/// until now rested on the preimage-order test plus the assumption that both
/// sides call the same primitive.
#[test]
fn pkg_tag_matches_python_golden_vector() {
    const GOLDEN: &str = "23b0562c1d1d7de1b096fa766000643c9ecaff6f433805e4c45aee49742cd9ee";

    let key: [u8; 32] = core::array::from_fn(|i| i as u8); // bytes(range(32))
    let nonce = [0x22u8; 16];
    let header: [u8; HDR_LEN] = core::array::from_fn(|i| i as u8); // bytes(range(48))
    let tag = compute_pkg_tag(&nonce, 0x0A0B_0C0D, 0x1112_1314, 336, &header, &RealHmac, &key);
    assert_eq!(hex(&tag), GOLDEN, "pkg_tag diverged from tools/test_attestation_guard.py");

    // And the same tag, reached through the public entry point: a package built
    // with the real HMAC round-trips, so the KAT constrains `parse_and_verify`'s
    // tag comparison too, not just `compute_pkg_tag`.
    let mut blob = std::vec![0u8; 336];
    for (i, b) in blob.iter_mut().enumerate().take(HDR_LEN) {
        *b = i as u8;
    }
    let mut pkg = Vec::new();
    pkg.extend_from_slice(&UPDATE_MAGIC.to_le_bytes());
    pkg.extend_from_slice(&nonce);
    pkg.extend_from_slice(&0x0A0B_0C0Du32.to_le_bytes());
    pkg.extend_from_slice(&0x1112_1314u32.to_le_bytes());
    pkg.extend_from_slice(&336u32.to_le_bytes());
    pkg.extend_from_slice(&blob);
    pkg.extend_from_slice(&tag);
    let r = parse_and_verify(&pkg, &nonce, &RealHmac, &key);
    assert!(matches!(r, Ok(ref u) if u.version == 0x1112_1314 && u.author_id == 0x0A0B_0C0D));
}

/// The label is domain separation, not decoration: v1's label under the v2
/// preimage is a different tag, so a v1 signer cannot produce a v2-accepted
/// package (and vice versa).
///
/// Where the discriminating power actually sits: the three `assert_eq!` below
/// pin the label and the preimage arithmetic, and they are what fails if either
/// drifts. The closing `assert_ne!` documents the domain separation but proves
/// little on its own — it could only fire on a 256-bit collision.
#[test]
fn v1_label_does_not_reproduce_the_v2_golden_tag() {
    assert_eq!(PKG_TAG_LABEL, b"umbra-update-v2");
    assert_eq!(PKG_TAG_LABEL.len(), 15);
    assert_eq!(PKG_PREIMAGE_LEN, 15 + 16 + 4 + 4 + 4 + HDR_LEN);

    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let nonce = [0x22u8; 16];
    let header: [u8; HDR_LEN] = core::array::from_fn(|i| i as u8);

    // Same 91-byte layout, v1 label — must NOT be the golden tag.
    let mut pre = [0u8; PKG_PREIMAGE_LEN];
    pre[0..15].copy_from_slice(b"umbra-update-v1");
    pre[15..31].copy_from_slice(&nonce);
    pre[31..35].copy_from_slice(&0x0A0B_0C0Du32.to_le_bytes());
    pre[35..39].copy_from_slice(&0x1112_1314u32.to_le_bytes());
    pre[39..43].copy_from_slice(&336u32.to_le_bytes());
    pre[43..91].copy_from_slice(&header);
    assert_ne!(
        hex(&hmac_sha256(&key, &pre)),
        "23b0562c1d1d7de1b096fa766000643c9ecaff6f433805e4c45aee49742cd9ee"
    );
}
