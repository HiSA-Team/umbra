#!/usr/bin/env python3
"""Pins the attestation-quote + secure-update byte layout so the Python verifier
(tools/attest_update.py) and the Rust firmware (kernel attestation.rs /
enclave_update.rs) stay byte-identical. Mirror of tools/test_enclave_version_guard.py.

Run: /opt/miniconda3/bin/python tools/test_attestation_guard.py
The Rust side asserts the SAME fixed tag vectors printed here (see the golden-vector
tests in attestation_tests.rs / enclave_update_tests.rs)."""
import hashlib
import hmac
import os
import re
import struct
import sys

# --- normative constants (must match the Rust modules) ---
QUOTE_MAGIC = 0x31545155   # "UQT1" little-endian bytes 55 51 54 31
QUOTE_PREIMAGE_LEN = 83
QUOTE_LEN = QUOTE_PREIMAGE_LEN + 32  # 115
UPDATE_MAGIC = 0x31505555  # "UUP1"
PKG_LABEL = b"umbra-update-v2"       # 15 bytes; v2 = full 48-byte header covered
PKG_PREIMAGE_LEN = 91                # 15 + 16 + 4 + 4 + 4 + 48
ATTEST_LABEL = b"umbra-attest-v1"
UPDATE_KEY_LABEL = b"umbra-update-key-v1"


def quote_preimage(nonce, enclave_id, status, bm, author, version, floor,
                   anchor_gen, restore, reset_cause, hdpl, flags):
    b = bytearray(QUOTE_PREIMAGE_LEN)
    struct.pack_into("<I", b, 0, QUOTE_MAGIC)
    b[4:20] = nonce
    struct.pack_into("<I", b, 20, enclave_id)
    b[24] = status
    b[25:57] = bm
    struct.pack_into("<I", b, 57, author)
    struct.pack_into("<I", b, 61, version)
    struct.pack_into("<I", b, 65, floor)
    struct.pack_into("<I", b, 69, anchor_gen)
    b[73] = restore
    struct.pack_into("<I", b, 74, reset_cause)
    b[78] = hdpl
    struct.pack_into("<I", b, 79, flags)
    return bytes(b)


def test_quote_offsets():
    # distinct byte pattern per field so a field swap changes the vector
    pre = quote_preimage(
        nonce=bytes(range(0x90, 0xA0)),
        enclave_id=0x01020304, status=0x61, bm=bytes(range(0xB0, 0xD0)),
        author=0x0A0B0C0D, version=0x11121314, floor=0x21222324,
        anchor_gen=0x31323334, restore=0x71, reset_cause=0x41424344,
        hdpl=0x81, flags=0x51525354,
    )
    assert len(pre) == QUOTE_PREIMAGE_LEN, len(pre)
    assert pre[0:4] == struct.pack("<I", QUOTE_MAGIC)
    assert pre[61:65] == struct.pack("<I", 0x11121314)   # version offset
    assert pre[74:78] == struct.pack("<I", 0x41424344)   # reset_cause offset
    key = bytes(range(32))
    tag = hmac.new(key, pre, hashlib.sha256).digest()
    # Regression pin: the full 83-byte preimage. The Rust golden test
    # (attestation_tests.rs::preimage_matches_golden_vector) builds the SAME bytes
    # from the SAME field values, so any layout drift on either side breaks parity.
    GOLDEN_PREIMAGE = (
        "55515431909192939495969798999a9b9c9d9e9f0403020161b0b1b2b3b4b5b6"
        "b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf0d0c0b0a141312"
        "11242322213433323171444342418154535251"
    )
    GOLDEN_TAG = "d2ab80e5a5f9922d78870c0f610675a1d7db37f822dcd1d424690e313663f02d"
    assert pre.hex() == GOLDEN_PREIMAGE, pre.hex()
    assert tag.hex() == GOLDEN_TAG, tag.hex()
    print("[quote]  preimage len =", len(pre), " golden tag =", tag.hex())


def compute_pkg_tag(key, nonce, author, version, blob_len, header):
    pre = PKG_LABEL + nonce + struct.pack("<III", author, version, blob_len) + header
    assert len(pre) == PKG_PREIMAGE_LEN, len(pre)
    return pre, hmac.new(key, pre, hashlib.sha256).digest()


def test_pkg_tag_preimage():
    nonce = bytes([0x22] * 16)
    header = bytes(range(0, 48))          # the FULL UMBR header, blob[0:48]
    key = bytes(range(32))
    pre, tag = compute_pkg_tag(key, nonce, 0x0A0B0C0D, 0x11121314, 336, header)
    assert pre[:15] == PKG_LABEL
    assert pre[15:31] == nonce
    assert pre[31:35] == struct.pack("<I", 0x0A0B0C0D)   # author
    assert pre[35:39] == struct.pack("<I", 0x11121314)   # version
    assert pre[39:43] == struct.pack("<I", 336)          # blob_len
    assert pre[43:91] == header                          # blob[0:48], all 48 bytes
    GOLDEN_TAG = "23b0562c1d1d7de1b096fa766000643c9ecaff6f433805e4c45aee49742cd9ee"
    assert tag.hex() == GOLDEN_TAG, tag.hex()
    print("[update] preimage len =", len(pre), " golden tag =", tag.hex())


def test_protocol_key_derivation():
    # Quote and update MACs use disjoint KDF labels. This separation is what
    # justifies omitting the quote oracle from the update-only EUF-CMA game.
    assert ATTEST_LABEL == b"umbra-attest-v1"
    assert UPDATE_KEY_LABEL == b"umbra-update-key-v1"
    master = bytes(range(32))
    ka = hmac.new(master, ATTEST_LABEL, hashlib.sha256).digest()
    ku = hmac.new(master, UPDATE_KEY_LABEL, hashlib.sha256).digest()
    assert ka != ku
    print("[key]    K_attest(master=0..31) =", ka.hex())
    print("[key]    K_update(master=0..31) =", ku.hex())


def test_protocol_labels_match_sources():
    """Pin the KDF labels in both executable protocol implementations."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rust_path = os.path.join(
        root, "src", "hardware", "platform", "stm32n657", "boot", "src",
        "key_derivation.rs",
    )
    signer_path = os.path.join(root, "tools", "attest_update.py")

    with open(rust_path) as f:
        rust = f.read()
    with open(signer_path) as f:
        signer = f.read()

    expected = {
        "ATTEST_KEY_LABEL": ATTEST_LABEL.decode("ascii"),
        "UPDATE_KEY_LABEL": UPDATE_KEY_LABEL.decode("ascii"),
    }
    for rust_name, label in expected.items():
        assert re.search(
            rf'pub const {rust_name}: &\[u8\] = b"{re.escape(label)}";', rust
        ), f"{rust_path}: {rust_name} does not encode {label!r}"

    assert re.search(
        r"pub fn derive_attest_key\b.*?\.hmac\(&MASTER_KEY, ATTEST_KEY_LABEL,",
        rust,
        re.DOTALL,
    ), f"{rust_path}: derive_attest_key is not wired to ATTEST_KEY_LABEL"
    assert re.search(
        r"pub fn derive_update_key\b.*?\.hmac\(&MASTER_KEY, UPDATE_KEY_LABEL,",
        rust,
        re.DOTALL,
    ), f"{rust_path}: derive_update_key is not wired to UPDATE_KEY_LABEL"

    assert re.search(
        rf'ATTEST_LABEL = b"{re.escape(expected["ATTEST_KEY_LABEL"])}"', signer
    ), f"{signer_path}: ATTEST_LABEL drifted"
    assert re.search(
        rf'UPDATE_KEY_LABEL = b"{re.escape(expected["UPDATE_KEY_LABEL"])}"', signer
    ), f"{signer_path}: UPDATE_KEY_LABEL drifted"
    assert "hmac.new(master, ATTEST_LABEL" in signer
    assert "hmac.new(master, UPDATE_KEY_LABEL" in signer
    print("[key]    Rust/Python KDF labels agree")


def test_master_key_copies_agree():
    """The four copies of the master key must hold the SAME 32 bytes.

    `tools/master_key.bin` is what the offline signer and this verifier read;
    each platform's `master_key.rs` is what the firmware compiles in. Nothing
    enforced that they agree, and they can be driven apart by ordinary use:
    `cargo xtask flash` reverts all four with `git checkout HEAD --` after a
    session (deliberately, so a rotated key is never committed), so whatever is
    committed becomes the live state — and the committed copies had drifted to
    four different keys. The board then answers every attestation quote with
    `tag: FAIL` while looking perfectly healthy, which is expensive to diagnose
    because it mimics a stale boot image.

    This check makes that state loud. It compares files on disk, so it passes
    trivially right after `gen_key.py` and fails exactly when the invariant has
    been broken.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bin_path = os.path.join(root, "tools", "master_key.bin")
    rs_paths = [
        os.path.join(root, "src", "hardware", "platform", p, "boot", "src", "master_key.rs")
        for p in ("stm32l552", "stm32n657", "riscv32")
    ]
    with open(bin_path, "rb") as f:
        key = f.read()
    assert len(key) == 32, f"{bin_path}: {len(key)} bytes, expected 32"

    bad = []
    for rs_path in rs_paths:
        with open(rs_path) as f:
            found = bytes(int(b, 16) for b in re.findall(r"0x([0-9A-Fa-f]{2})", f.read()))
        if found[:32] != key:
            bad.append(f"{os.path.relpath(rs_path, root)} = {found[:8].hex()}...")
    assert not bad, (
        "master key copies disagree with tools/master_key.bin ("
        + key[:8].hex()
        + "...):\n  "
        + "\n  ".join(bad)
        + "\nRepair with: UMBRA_KEEP_MASTER_KEY=1 python tools/gen_key.py"
    )
    print("[key]    4 master-key copies agree:", key[:8].hex() + "...")


if __name__ == "__main__":
    test_quote_offsets()
    test_pkg_tag_preimage()
    test_protocol_key_derivation()
    test_protocol_labels_match_sources()
    test_master_key_copies_agree()
    print("ALL PARITY VECTORS PASS")
    sys.exit(0)
