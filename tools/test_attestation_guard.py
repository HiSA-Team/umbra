#!/usr/bin/env python3
"""Pins the attestation-quote + secure-update byte layout so the Python verifier
(tools/attest_update.py) and the Rust firmware (kernel attestation.rs /
enclave_update.rs) stay byte-identical. Mirror of tools/test_enclave_version_guard.py.

Run: /opt/miniconda3/bin/python tools/test_attestation_guard.py
The Rust side asserts the SAME fixed tag vectors printed here (see the golden-vector
tests in attestation_tests.rs / enclave_update_tests.rs)."""
import hashlib
import hmac
import struct
import sys

# --- normative constants (must match the Rust modules) ---
QUOTE_MAGIC = 0x31545155   # "UQT1" little-endian bytes 55 51 54 31
QUOTE_PREIMAGE_LEN = 83
QUOTE_LEN = QUOTE_PREIMAGE_LEN + 32  # 115
UPDATE_MAGIC = 0x31505555  # "UUP1"
PKG_LABEL = b"umbra-update-v1"       # 15 bytes
PKG_PREIMAGE_LEN = 75                # 15 + 16 + 4 + 4 + 4 + 32
ATTEST_LABEL = b"umbra-attest-v1"


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


def compute_pkg_tag(key, nonce, author, version, blob_len, header_hmac):
    pre = PKG_LABEL + nonce + struct.pack("<III", author, version, blob_len) + header_hmac
    assert len(pre) == PKG_PREIMAGE_LEN, len(pre)
    return pre, hmac.new(key, pre, hashlib.sha256).digest()


def test_pkg_tag_preimage():
    nonce = bytes([0x22] * 16)
    header_hmac = bytes(range(16, 48))
    key = bytes(range(32))
    pre, tag = compute_pkg_tag(key, nonce, 0x0A0B0C0D, 0x11121314, 336, header_hmac)
    assert pre[:15] == PKG_LABEL
    assert pre[15:31] == nonce
    assert pre[31:35] == struct.pack("<I", 0x0A0B0C0D)   # author
    assert pre[35:39] == struct.pack("<I", 0x11121314)   # version
    GOLDEN_TAG = "2002304a5d6978ff02cb58900da7e25a5fcb9112727ba6d19ff459dc22c90d43"
    assert tag.hex() == GOLDEN_TAG, tag.hex()
    print("[update] preimage len =", len(pre), " golden tag =", tag.hex())


def test_kattest_derivation():
    # The verifier derives K_attest = HMAC(MASTER_KEY, "umbra-attest-v1"); pin the label.
    assert ATTEST_LABEL == b"umbra-attest-v1"
    master = bytes(range(32))
    k = hmac.new(master, ATTEST_LABEL, hashlib.sha256).digest()
    print("[key]    K_attest(master=0..31) =", k.hex())


if __name__ == "__main__":
    test_quote_offsets()
    test_pkg_tag_preimage()
    test_kattest_derivation()
    print("ALL PARITY VECTORS PASS")
    sys.exit(0)
