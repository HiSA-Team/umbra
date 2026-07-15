use super::*;

// Streaming mock HMAC: concatenate all parts, fold with a trivial keyed sum.
// Deterministic and order-sensitive so it catches field-order regressions.
fn mock_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut acc: [u8; 32] = [0; 32];
    let mut n: usize = 0;
    for &b in key {
        acc[n % 32] = acc[n % 32].wrapping_add(b).wrapping_add(1);
        n += 1;
    }
    for p in parts {
        for &b in *p {
            acc[n % 32] = acc[n % 32].wrapping_add(b).wrapping_add(2);
            n += 1;
        }
    }
    acc
}

/// Every field carries a DISTINCT byte pattern, so swapping any two fields
/// (or shifting an offset) changes the serialized preimage and fails the tests.
fn sample() -> QuoteFields {
    let mut nonce = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        nonce[i] = 0x90 + i as u8; // 0x90..=0x9F
        i += 1;
    }
    let mut bm = [0u8; 32];
    let mut j = 0;
    while j < 32 {
        bm[j] = 0xB0u8.wrapping_add(j as u8); // 0xB0..=0xCF
        j += 1;
    }
    QuoteFields {
        nonce,
        enclave_id: 0x0102_0304,
        status: 0x61,
        bm,
        author_id: 0x0A0B_0C0D,
        version: 0x1112_1314,
        floor: 0x2122_2324,
        anchor_gen: 0x3132_3334,
        restore: 0x71,
        reset_cause: 0x4142_4344,
        hdpl: 0x81,
        flags: 0x5152_5354,
    }
}

#[test]
fn preimage_len_is_exact() {
    let q = sample();
    let mut buf = [0u8; QUOTE_PREIMAGE_LEN];
    let n = q.write_preimage(&mut buf);
    assert_eq!(n, QUOTE_PREIMAGE_LEN);
}

#[test]
fn serialized_quote_has_tag_appended_at_fixed_offset() {
    let q = sample();
    let key = [0x5A; 32];
    let mut out = [0u8; QUOTE_LEN];
    build_quote(&q, &key, mock_hmac, &mut out);
    // magic first
    assert_eq!(&out[0..4], &QUOTE_MAGIC.to_le_bytes());
    // tag == mock_hmac(key, [preimage])
    let mut pre = [0u8; QUOTE_PREIMAGE_LEN];
    q.write_preimage(&mut pre);
    let expect = mock_hmac(&key, &[&pre]);
    assert_eq!(&out[QUOTE_PREIMAGE_LEN..QUOTE_LEN], &expect[..]);
}

#[test]
fn nonce_binds_the_tag() {
    let key = [0x5A; 32];
    let mut a = [0u8; QUOTE_LEN];
    let mut b = [0u8; QUOTE_LEN];
    let mut q = sample();
    build_quote(&q, &key, mock_hmac, &mut a);
    q.nonce[0] ^= 0xFF;
    build_quote(&q, &key, mock_hmac, &mut b);
    assert_ne!(&a[QUOTE_PREIMAGE_LEN..], &b[QUOTE_PREIMAGE_LEN..]);
}

#[test]
fn version_field_is_at_documented_offset() {
    let q = sample();
    let mut buf = [0u8; QUOTE_PREIMAGE_LEN];
    q.write_preimage(&mut buf);
    // offset 61 per the layout table
    assert_eq!(&buf[61..65], &0x1112_1314u32.to_le_bytes());
}

/// Executable form of the NORMATIVE layout table in `attestation.rs`: the full
/// expected 83-byte preimage is built by hand, field by field at explicit
/// offsets, and compared byte-for-byte against `write_preimage`. Any offset
/// shift, field swap, or endianness change fails here.
#[test]
fn preimage_matches_golden_vector() {
    let q = sample();
    let mut buf = [0u8; QUOTE_PREIMAGE_LEN];
    q.write_preimage(&mut buf);

    let mut expected = [0u8; QUOTE_PREIMAGE_LEN];
    // off 0, size 4: magic "UQT1" little-endian
    expected[0..4].copy_from_slice(&[0x55, 0x51, 0x54, 0x31]);
    // off 4, size 16: nonce = 0x90..=0x9F
    expected[4..20].copy_from_slice(&[
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
        0x9E, 0x9F,
    ]);
    // off 20, size 4: enclave_id = 0x01020304 LE
    expected[20..24].copy_from_slice(&[0x04, 0x03, 0x02, 0x01]);
    // off 24, size 1: status
    expected[24] = 0x61;
    // off 25, size 32: bm = 0xB0..=0xCF
    let mut j = 0;
    while j < 32 {
        expected[25 + j] = 0xB0u8.wrapping_add(j as u8);
        j += 1;
    }
    // off 57, size 4: author_id = 0x0A0B0C0D LE
    expected[57..61].copy_from_slice(&[0x0D, 0x0C, 0x0B, 0x0A]);
    // off 61, size 4: version = 0x11121314 LE
    expected[61..65].copy_from_slice(&[0x14, 0x13, 0x12, 0x11]);
    // off 65, size 4: floor = 0x21222324 LE
    expected[65..69].copy_from_slice(&[0x24, 0x23, 0x22, 0x21]);
    // off 69, size 4: anchor_gen = 0x31323334 LE
    expected[69..73].copy_from_slice(&[0x34, 0x33, 0x32, 0x31]);
    // off 73, size 1: restore
    expected[73] = 0x71;
    // off 74, size 4: reset_cause = 0x41424344 LE
    expected[74..78].copy_from_slice(&[0x44, 0x43, 0x42, 0x41]);
    // off 78, size 1: hdpl
    expected[78] = 0x81;
    // off 79, size 4: flags = 0x51525354 LE
    expected[79..83].copy_from_slice(&[0x54, 0x53, 0x52, 0x51]);

    assert_eq!(&buf[..], &expected[..]);
}
