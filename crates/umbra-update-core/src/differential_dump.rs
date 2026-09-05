//! Differential Rust-vs-vm_compute corpus dumper.
//!
//! Runs the crate's `parse_and_verify` on every package the sibling tests
//! build (plus two extras: a bad-magic package and one signed with a REAL
//! HMAC-SHA-256), records the bytes and the verdict the Rust crate returned,
//! and writes them as `list Z` literals plus one `Theorem` per vector into
//! `formal/rocq/update-core/proofs-coq/Update_Differential.v`, where the
//! extracted `parse_and_verify` re-runs each vector under `vm_compute`
//! (seams: `Update_DifferentialSeams.v`).
//!
//! Gated: `UMBRA_DUMP_DIFFERENTIAL` unset -> the test only builds the corpus
//! in memory (normal `cargo test` unchanged). `=1` -> write the checked-in
//! file. Any other value -> write to that path (the artifact preflight dumps
//! to a temp file and diffs it against the checked-in one).
//!
//! Verdicts are what the crate computed, not hand-written expectations: the
//! sibling tests pin the semantics, this file pins Rust == extraction.
//!
//! Device corpus: `UMBRA_DIFFERENTIAL_DEVICE=<file>` adds the packages the
//! host actually sent to the N657 during the campaign, recorded by
//! `tools/attest_update.py --dump` (one line each: name, device status,
//! armed nonce, package, seam kind, signed preimage, tag; hex). Every
//! real-key (preimage, tag) pair becomes an entry of one shared `table_seam`
//! under a dummy key (both sides look up by preimage), the crate re-judges
//! each package, and its verdict class must agree with the device's status
//! word or this test panics: device == Rust == extraction on the same bytes.
//! The first two lines per (name, status) are kept, so twenty replays of one
//! class do not become twenty theorems.

extern crate std;
use super::{dummy_blob, hmac_sha256, make_pkg, MockHmac};
use crate::*;
use core::cell::RefCell;
use core::fmt::Write as _;
use std::string::String;
use std::vec::Vec;

const OUT_REL: &str = "../../formal/rocq/update-core/proofs-coq/Update_Differential.v";
const FUZZ_OUT_REL: &str = "../../formal/rocq/update-core/proofs-coq/Update_DifferentialFuzz.v";
/// Mutated corpus: `FUZZ_N` packages derived from the base accepted package by
/// one mutation each (byte flip, length edit, field edit, header flip); even
/// indices are re-signed from their own declared fields under the mock seam so
/// accepts and structural rejections occur, odd ones keep the stale tag.
const FUZZ_N: usize = 1000;
const FUZZ_SEED: u64 = 0x5EED_DA7E_2026_0905;

enum Verdict {
    Ok {
        author: u32,
        version: u32,
        blob: Vec<u8>,
    },
    Err(UpdateError),
}

enum Seam {
    Mock,
    /// Real HMAC-SHA-256: the seam is a lookup over the recorded triple.
    Table {
        key: Vec<u8>,
        pre: [u8; PKG_PREIMAGE_LEN],
        tag: [u8; 32],
    },
    /// Device corpus: the shared table of every real-key (preimage, tag) the
    /// campaign signer produced, under `DEVICE_KEY`.
    Device,
}

struct Vector {
    name: String,
    origin: String,
    seam: Seam,
    key: Vec<u8>,
    pkg: Vec<u8>,
    nonce: [u8; 16],
    verdict: Verdict,
}

/// Dummy key shared by both sides of the device corpus: the table seam looks
/// up by preimage, so the real `K_update` never leaves the signer.
const DEVICE_KEY: [u8; 32] = [0u8; 32];

/// Table seam over (preimage -> tag), key ignored; the Rocq `table_seam` gets
/// the same entries under `DEVICE_KEY`.
struct DeviceHmac(Vec<([u8; PKG_PREIMAGE_LEN], [u8; 32])>);
impl PkgHmac for DeviceHmac {
    fn hmac_pkg(&self, _key: &[u8], pre: &[u8; PKG_PREIMAGE_LEN]) -> [u8; 32] {
        self.0
            .iter()
            .find(|(p, _)| p == pre)
            .map(|(_, t)| *t)
            .unwrap_or([0u8; 32])
    }
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length in device corpus");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

// Device status words (tools/attest_update.py, attest_imp.rs) and the crate
// verdict class each one implies. ERR_ARG can be the parser's Malformed /
// BadMagic or the handler's exact-length rule after a parser Ok.
const ST_OK: u32 = 0;
const ST_NONCE: u32 = 0xFFFF_FF20;
const ST_AUTH: u32 = 0xFFFF_FF21;
const ST_VERIFY: u32 = 0xFFFF_FF22;
const ST_ROLLBACK: u32 = 0xFFFF_FF23;
const ST_FLASH: u32 = 0xFFFF_FF24;
const ST_ARG: u32 = 0xFFFF_FFF6;

fn status_agrees(status: u32, v: &Verdict) -> bool {
    match (status, v) {
        (ST_OK | ST_VERIFY | ST_ROLLBACK | ST_FLASH, Verdict::Ok { .. }) => true,
        (ST_NONCE, Verdict::Err(UpdateError::NonceMismatch)) => true,
        (ST_AUTH, Verdict::Err(UpdateError::TagInvalid)) => true,
        (ST_ARG, Verdict::Err(UpdateError::Malformed | UpdateError::BadMagic)) => true,
        (ST_ARG, Verdict::Ok { .. }) => true,
        _ => false,
    }
}

/// Parse `--dump` lines; returns (table entries, vectors). Lines whose status is
/// unknown ('-') or a device-state code (busy) are skipped and counted.
fn device_corpus(text: &str) -> (Vec<([u8; PKG_PREIMAGE_LEN], [u8; 32])>, Vec<Vector>) {
    let mut table: Vec<([u8; PKG_PREIMAGE_LEN], [u8; 32])> = Vec::new();
    let mut rows = Vec::new();
    for (ln, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 7, "device corpus line {}: expected 7 fields", ln + 1);
        if f[4] == "real" {
            let pre: [u8; PKG_PREIMAGE_LEN] = unhex(f[5]).try_into().expect("91-byte preimage");
            let tag: [u8; 32] = unhex(f[6]).try_into().expect("32-byte tag");
            if !table.iter().any(|(p, _)| *p == pre) {
                table.push((pre, tag));
            }
        }
        rows.push((ln + 1, String::from(f[0]), String::from(f[1]), unhex(f[2]), unhex(f[3])));
    }
    let seam = DeviceHmac(table.clone());
    let mut kept: Vec<(String, String)> = Vec::new();
    let mut vs = Vec::new();
    let mut skipped = 0usize;
    for (ln, name, st, armed, pkg) in rows {
        let Ok(status) = u32::from_str_radix(&st, 16) else {
            skipped += 1;
            continue;
        };
        // Cap per (class, status): `update-v17` and `update-v18` are one class.
        let class = match name.rsplit_once("-v") {
            Some((c, d)) if !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()) => {
                String::from(c)
            }
            _ => name.clone(),
        };
        if kept.iter().filter(|(n, s)| *n == class && *s == st).count() >= 2 {
            continue;
        }
        let nonce: [u8; 16] = armed.try_into().expect("16-byte armed nonce");
        let verdict = verdict_of(parse_and_verify(&pkg, &nonce, &seam, &DEVICE_KEY));
        assert!(
            status_agrees(status, &verdict),
            "device corpus line {ln} ({name}): device status 0x{status:08x} disagrees with the crate's verdict"
        );
        kept.push((class, st.clone()));
        vs.push(Vector {
            name: std::format!("dev_{}_{}", vs.len() + 1, name.replace('-', "_")),
            origin: std::format!("device corpus line {ln}, class `{name}`, device status 0x{status:08x}"),
            seam: Seam::Device,
            key: Vec::from(&DEVICE_KEY[..]),
            pkg,
            nonce,
            verdict,
        });
    }
    if skipped > 0 {
        std::eprintln!("differential: {skipped} device corpus line(s) without a status word skipped");
    }
    (table, vs)
}

/// (key, 91-byte preimage, tag) as handed to / returned by the seam.
type SeamCall = (Vec<u8>, [u8; PKG_PREIMAGE_LEN], [u8; 32]);

/// A real-HMAC seam that records what the crate handed it.
struct RecordingHmac(RefCell<Vec<SeamCall>>);
impl PkgHmac for RecordingHmac {
    fn hmac_pkg(&self, key: &[u8], pre: &[u8; PKG_PREIMAGE_LEN]) -> [u8; 32] {
        let tag = hmac_sha256(key, pre);
        self.0.borrow_mut().push((Vec::from(key), *pre, tag));
        tag
    }
}

fn verdict_of(r: Result<VerifiedUpdate<'_>, UpdateError>) -> Verdict {
    match r {
        Ok(u) => Verdict::Ok {
            author: u.author_id,
            version: u.version,
            blob: Vec::from(u.blob),
        },
        Err(e) => Verdict::Err(e),
    }
}

fn mock_vec(
    name: &'static str,
    origin: &'static str,
    key: &[u8],
    pkg: Vec<u8>,
    nonce: [u8; 16],
) -> Vector {
    let verdict = verdict_of(parse_and_verify(&pkg, &nonce, &MockHmac, key));
    Vector {
        name: String::from(name),
        origin: String::from(origin),
        seam: Seam::Mock,
        key: Vec::from(key),
        pkg,
        nonce,
        verdict,
    }
}

fn corpus() -> Vec<Vector> {
    let key = [0x5Au8; 32];
    let nonce = [0x22u8; 16];
    let blob = dummy_blob();
    let base = make_pkg(nonce, 1, 3, &blob, &key);
    let mut v = Vec::new();

    v.push(mock_vec(
        "accept",
        "accepts_matching_nonce_and_tag",
        &key,
        base.clone(),
        nonce,
    ));

    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 1;
    v.push(mock_vec(
        "wrong_nonce",
        "rejects_wrong_nonce",
        &key,
        base.clone(),
        bad_nonce,
    ));

    let mut tampered = base.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    v.push(mock_vec(
        "tampered_tag",
        "rejects_tampered_tag",
        &key,
        tampered,
        nonce,
    ));

    v.push(mock_vec(
        "truncated",
        "rejects_truncated_package",
        &key,
        std::vec![0u8; 8],
        nonce,
    ));

    for (name, off) in [
        ("flip_hdr4", 4usize),
        ("flip_hdr6", 6),
        ("flip_hdr8", 8),
        ("flip_hdr14", 14),
    ] {
        let mut t = base.clone();
        t[32 + off] ^= 0x01;
        v.push(mock_vec(
            name,
            "rejects_post_signing_flip_of_formerly_unauthenticated_header_bytes",
            &key,
            t,
            nonce,
        ));
    }

    let mut huge = make_pkg(nonce, 0x0A0B0C0D, 0x1112_1314, &blob, &key);
    huge[28..32].copy_from_slice(&0xFFFF_FFC0_u32.to_le_bytes());
    v.push(mock_vec(
        "huge_blob_len",
        "huge_blob_len_is_malformed_not_panic",
        &key,
        huge,
        nonce,
    ));

    let nonce11 = [0x11u8; 16];
    let mut min_blob = std::vec![0u8; 48];
    for (i, b) in min_blob.iter_mut().enumerate() {
        *b = (0x80 + i) as u8;
    }
    v.push(mock_vec(
        "min_blob",
        "accepts_exactly_min_blob",
        &key,
        make_pkg(nonce11, 7, 9, &min_blob, &key),
        nonce11,
    ));

    // Extra: no sibling test covers BadMagic; the adversarial class is cheap.
    let mut bad_magic = base.clone();
    bad_magic[0] ^= 0x01;
    v.push(mock_vec(
        "bad_magic",
        "(added by the dumper: BadMagic path)",
        &key,
        bad_magic,
        nonce,
    ));

    // Real tag: the Python golden vector (tools/test_attestation_guard.py ::
    // test_pkg_tag_preimage), built through the crate under a real
    // HMAC-SHA-256. tools/attest_update.py::build_pkg with the same key
    // emits byte-identical package bytes.
    let rkey: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut rblob = std::vec![0u8; 336];
    for (i, b) in rblob.iter_mut().enumerate().take(HDR_LEN) {
        *b = i as u8;
    }
    let rec = RecordingHmac(RefCell::new(Vec::new()));
    let mut header = [0u8; HDR_LEN];
    header.copy_from_slice(&rblob[..HDR_LEN]);
    let tag = compute_pkg_tag(&nonce, 0x0A0B_0C0D, 0x1112_1314, 336, &header, &rec, &rkey);
    let mut rpkg = Vec::new();
    rpkg.extend_from_slice(&UPDATE_MAGIC.to_le_bytes());
    rpkg.extend_from_slice(&nonce);
    rpkg.extend_from_slice(&0x0A0B_0C0Du32.to_le_bytes());
    rpkg.extend_from_slice(&0x1112_1314u32.to_le_bytes());
    rpkg.extend_from_slice(&336u32.to_le_bytes());
    rpkg.extend_from_slice(&rblob);
    rpkg.extend_from_slice(&tag);
    let verdict = verdict_of(parse_and_verify(&rpkg, &nonce, &rec, &rkey));
    let calls = rec.0.into_inner();
    assert_eq!(
        calls.len(),
        2,
        "sign + verify must each query the seam once"
    );
    assert!(
        calls[0] == calls[1],
        "sign and verify must hand the seam the same (key, preimage)"
    );
    let (k, pre, tag) = calls[0].clone();
    v.push(Vector {
        name: String::from("real_tag"),
        origin: String::from("pkg_tag_matches_python_golden_vector (real HMAC-SHA-256, table seam)"),
        seam: Seam::Table { key: k, pre, tag },
        key: Vec::from(&rkey[..]),
        pkg: rpkg,
        nonce,
        verdict,
    });
    v
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Re-sign a package from its own declared fields (nonce, author, version,
/// blob_len, header = bytes [32, 80)) under the mock seam, overwriting the
/// trailing 32 bytes. Packages too short to carry a header are left as they are.
fn resign(pkg: &mut [u8], key: &[u8]) -> bool {
    if pkg.len() < 32 + HDR_LEN + 32 {
        return false;
    }
    let nonce: [u8; 16] = pkg[4..20].try_into().unwrap();
    let u = |o: usize| u32::from_le_bytes(pkg[o..o + 4].try_into().unwrap());
    let (author, version, blob_len) = (u(20), u(24), u(28));
    let header: [u8; HDR_LEN] = pkg[32..32 + HDR_LEN].try_into().unwrap();
    let tag = compute_pkg_tag(&nonce, author, version, blob_len, &header, &MockHmac, key);
    let n = pkg.len();
    pkg[n - 32..].copy_from_slice(&tag);
    true
}

fn fuzz_corpus() -> Vec<Vector> {
    let key = [0x5Au8; 32];
    let nonce = [0x22u8; 16];
    let blob = dummy_blob();
    let base = make_pkg(nonce, 1, 3, &blob, &key);
    let mut rng = XorShift(FUZZ_SEED);
    let mut v = Vec::new();
    for i in 0..FUZZ_N {
        let mut p = base.clone();
        let what = match rng.below(4) {
            0 => {
                let off = rng.below(p.len());
                let bit = 1u8 << rng.below(8);
                p[off] ^= bit;
                std::format!("flip byte {off} mask 0x{bit:02x}")
            }
            1 => {
                if rng.next() & 1 == 0 {
                    let len = rng.below(p.len());
                    p.truncate(len);
                    std::format!("truncate to {len} bytes")
                } else {
                    let k = 1 + rng.below(64);
                    for _ in 0..k {
                        p.push(rng.next() as u8);
                    }
                    std::format!("extend by {k} random bytes")
                }
            }
            2 => {
                let val = rng.next() as u32;
                match rng.below(4) {
                    0 => {
                        let j = rng.below(16);
                        p[4 + j] = val as u8;
                        std::format!("nonce byte {j} := 0x{:02x}", val as u8)
                    }
                    f => {
                        let off = 16 + 4 * f; // 20 author, 24 version, 28 blob_len
                        p[off..off + 4].copy_from_slice(&val.to_le_bytes());
                        std::format!("field at {off} := 0x{val:08x}")
                    }
                }
            }
            _ => {
                let off = 32 + rng.below(HDR_LEN);
                let bit = 1u8 << rng.below(8);
                p[off] ^= bit;
                std::format!("header byte {off} mask 0x{bit:02x}")
            }
        };
        let signed = i % 2 == 0 && resign(&mut p, &key);
        let verdict = verdict_of(parse_and_verify(&p, &nonce, &MockHmac, &key));
        v.push(Vector {
            name: std::format!("fuzz_{}", i + 1),
            origin: std::format!("{what}{}", if signed { ", re-signed" } else { "" }),
            seam: Seam::Mock,
            key: Vec::from(&key[..]),
            pkg: p,
            nonce,
            verdict,
        });
    }
    v
}

fn histogram(vs: &[Vector]) -> String {
    let mut c = [0usize; 5]; // Ok, Malformed, BadMagic, NonceMismatch, TagInvalid
    for v in vs {
        c[match &v.verdict {
            Verdict::Ok { .. } => 0,
            Verdict::Err(UpdateError::Malformed) => 1,
            Verdict::Err(UpdateError::BadMagic) => 2,
            Verdict::Err(UpdateError::NonceMismatch) => 3,
            Verdict::Err(UpdateError::TagInvalid) => 4,
        }] += 1;
    }
    std::format!(
        "Ok {}, Malformed {}, BadMagic {}, NonceMismatch {}, TagInvalid {}",
        c[0], c[1], c[2], c[3], c[4]
    )
}

const SELECTOR: [(Option<u32>, Option<u32>); 6] = [
    (Some(2), Some(5)),
    (Some(5), Some(2)),
    (Some(3), Some(3)),
    (Some(2), None),
    (None, Some(4)),
    (None, None),
];

fn zlist(out: &mut String, name: &str, bytes: &[u8]) {
    let _ = write!(out, "Definition {name} : list Z := [");
    for (i, b) in bytes.iter().enumerate() {
        if i % 24 == 0 {
            out.push_str(if i == 0 { "\n  " } else { ";\n  " });
        } else {
            out.push_str("; ");
        }
        let _ = write!(out, "{b}");
    }
    out.push_str("].\n");
}

fn opt(o: Option<u32>) -> String {
    match o {
        Some(x) => std::format!("(Some {x}%u32)"),
        None => String::from("None"),
    }
}

fn render(
    vs: &[Vector],
    device_table: &[([u8; PKG_PREIMAGE_LEN], [u8; 32])],
    with_selectors: bool,
    note: &str,
) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "(** GENERATED by `{}=1 cargo test -p umbra-update-core`",
        if with_selectors { "UMBRA_DUMP_DIFFERENTIAL" } else { "UMBRA_DUMP_DIFFERENTIAL_FUZZ" }
    );
    o.push_str("    (crates/umbra-update-core/src/differential_dump.rs). DO NOT EDIT.\n\n");
    if !note.is_empty() {
        let _ = writeln!(o, "    {note}\n");
    }
    o.push_str("    Differential Rust-vs-vm_compute check: every package below was built and\n");
    o.push_str("    judged by the RUST crate (`parse_and_verify` under the test MockHmac, or\n");
    o.push_str("    under a real HMAC-SHA-256 for `real_tag`); each theorem re-runs the\n");
    o.push_str("    EXTRACTED `parse_and_verify` on the same bytes and checks that the verdict\n");
    o.push_str("    and the returned fields agree. Seams and `verdict_of`: Update_DifferentialSeams.v. *)\n\n");
    o.push_str("Require Import Primitives.\nImport Primitives.\n");
    o.push_str("Require Import Coq.ZArith.ZArith.\nRequire Import Coq.Lists.List.\nImport ListNotations.\n");
    o.push_str("Require Import Update_Types.\nImport Update_Types.\n");
    o.push_str("Require Import Update_FunsExternal.\nImport Update_FunsExternal.\n");
    o.push_str("Require Import Update_Funs.\nImport Update_Funs.\n");
    o.push_str("Require Import Update_DifferentialSeams.\n");
    o.push_str("Local Open Scope Z_scope.\nLocal Open Scope Primitives_scope.\n\n");

    let mut all_lists: Vec<String> = Vec::new();
    if !device_table.is_empty() {
        o.push_str("(* ---- device corpus: every real-key (preimage, tag) the campaign signer\n");
        o.push_str("   produced, under the shared dummy key; lookup is by preimage ---- *)\n");
        zlist(&mut o, "dkey", &DEVICE_KEY);
        all_lists.push(String::from("dkey"));
        let mut entries = Vec::new();
        for (i, (pre, tag)) in device_table.iter().enumerate() {
            let i = i + 1;
            zlist(&mut o, &std::format!("dpre_{i}"), pre);
            zlist(&mut o, &std::format!("dtag_{i}"), tag);
            all_lists.push(std::format!("dpre_{i}"));
            all_lists.push(std::format!("dtag_{i}"));
            entries.push(std::format!("(dkey, dpre_{i}, dtag_{i})"));
        }
        let _ = writeln!(
            o,
            "Definition device_table : list table_entry := [{}].",
            entries.join("; ")
        );
        o.push_str("Definition device_seam := table_seam device_table.\n\n");
    }
    for (n, v) in vs.iter().enumerate() {
        let n = n + 1;
        let _ = writeln!(
            o,
            "(* ---- vector {n}: {} — Rust test `{}` ---- *)",
            v.name, v.origin
        );
        zlist(&mut o, &std::format!("key_{n}"), &v.key);
        zlist(&mut o, &std::format!("pkg_{n}"), &v.pkg);
        zlist(&mut o, &std::format!("en_{n}"), &v.nonce);
        all_lists.push(std::format!("key_{n}"));
        all_lists.push(std::format!("pkg_{n}"));
        all_lists.push(std::format!("en_{n}"));
        let seam = match &v.seam {
            Seam::Mock => String::from("mock_seam"),
            Seam::Table { key, pre, tag } => {
                zlist(&mut o, &std::format!("tkey_{n}"), key);
                zlist(&mut o, &std::format!("tpre_{n}"), pre);
                zlist(&mut o, &std::format!("ttag_{n}"), tag);
                all_lists.push(std::format!("tkey_{n}"));
                all_lists.push(std::format!("tpre_{n}"));
                all_lists.push(std::format!("ttag_{n}"));
                let _ = writeln!(
                    o,
                    "Definition seam_{n} := table_seam [(tkey_{n}, tpre_{n}, ttag_{n})]."
                );
                std::format!("seam_{n}")
            }
            Seam::Device => String::from("device_seam"),
        };
        let expected = match &v.verdict {
            Verdict::Ok {
                author,
                version,
                blob,
            } => {
                zlist(&mut o, &std::format!("blob_{n}"), blob);
                all_lists.push(std::format!("blob_{n}"));
                std::format!("V_Ok {author} {version} blob_{n}")
            }
            Verdict::Err(e) => {
                let c = match e {
                    UpdateError::Malformed => "Malformed",
                    UpdateError::BadMagic => "BadMagic",
                    UpdateError::NonceMismatch => "NonceMismatch",
                    UpdateError::TagInvalid => "TagInvalid",
                };
                std::format!("V_Err UpdateError_{c}")
            }
        };
        let _ = writeln!(o, "Definition key_{n}s : slice u8.");
        let _ = writeln!(
            o,
            "Proof. refine (exist _ (map byte key_{n}) _). vm_compute. discriminate. Defined."
        );
        let _ = writeln!(o, "Definition pkg_{n}s : slice u8.");
        let _ = writeln!(
            o,
            "Proof. refine (exist _ (map byte pkg_{n}) _). vm_compute. discriminate. Defined."
        );
        let _ = writeln!(o, "Definition en_{n}a : array u8 16%usize.");
        let _ = writeln!(
            o,
            "Proof. refine (exist _ (map byte en_{n}) _). vm_compute. reflexivity. Defined."
        );
        let _ = writeln!(o, "Theorem vec_{n} :");
        let _ = writeln!(
            o,
            "  verdict_of (parse_and_verify {seam} pkg_{n}s en_{n}a tt key_{n}s) = {expected}."
        );
        let _ = writeln!(o, "Proof. vm_compute. reflexivity. Qed.\n");
    }

    if with_selectors {
        o.push_str("(* ---- select_active_slot: the six cases of `selects_higher_authenticated_version` ---- *)\n");
        for (i, (a, b)) in SELECTOR.iter().enumerate() {
            let n = i + 1;
            let exp = match select_active_slot(*a, *b) {
                Some(s) => std::format!("Some {s}"),
                None => String::from("None"),
            };
            let _ = writeln!(
                o,
                "Theorem slot_{n} : slot_of (select_active_slot {} {}) = {exp}.",
                opt(*a),
                opt(*b)
            );
            let _ = writeln!(o, "Proof. vm_compute. reflexivity. Qed.");
        }
    }

    o.push_str("\n(* Every emitted value is a byte, so `byte` never clamped. *)\n");
    o.push_str("Theorem all_bytes_in_range :\n  forallb in_byte_range (");
    o.push_str(&all_lists.join(" ++ "));
    o.push_str(") = true.\nProof. vm_compute. reflexivity. Qed.\n");
    let ndev = vs.iter().filter(|v| matches!(v.seam, Seam::Device)).count();
    let _ = writeln!(
        o,
        "\n(* {} package vectors ({} from the device corpus), {} selector vectors. *)",
        vs.len(),
        ndev,
        if with_selectors { SELECTOR.len() } else { 0 }
    );
    o.push_str("Print Assumptions vec_1.\n");
    o
}

fn write_if_requested(var: &str, rel: &str, text: &str) {
    let Some(target) = std::env::var_os(var) else {
        return;
    };
    let path = if target == "1" {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
    } else {
        std::path::PathBuf::from(target)
    };
    std::fs::write(&path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

#[test]
fn dump_fuzz_corpus() {
    let vs = fuzz_corpus();
    assert_eq!(vs.len(), FUZZ_N);
    let note = std::format!(
        "Mutated corpus: {FUZZ_N} packages, xorshift64 seed 0x{FUZZ_SEED:016x}, one mutation each, even indices re-signed under the mock seam. Verdicts: {}.",
        histogram(&vs)
    );
    write_if_requested("UMBRA_DUMP_DIFFERENTIAL_FUZZ", FUZZ_OUT_REL, &render(&vs, &[], false, &note));
}

#[test]
fn dump_differential_corpus() {
    let mut vs = corpus();
    assert_eq!(vs.len(), 12);
    let mut device_table = Vec::new();
    if let Some(p) = std::env::var_os("UMBRA_DIFFERENTIAL_DEVICE").filter(|p| !p.is_empty()) {
        // cargo runs tests in the crate directory; a repo-relative path is
        // resolved against the workspace root when it does not exist as given.
        let mut path = std::path::PathBuf::from(&p);
        if path.is_relative() && !path.exists() {
            path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(&path);
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read UMBRA_DIFFERENTIAL_DEVICE {}: {e}", path.display()));
        let (t, dv) = device_corpus(&text);
        device_table = t;
        vs.extend(dv);
    }
    let text = render(&vs, &device_table, true, "");
    write_if_requested("UMBRA_DUMP_DIFFERENTIAL", OUT_REL, &text);
}
