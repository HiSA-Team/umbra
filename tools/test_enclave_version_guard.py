"""Guard test for the enclave version-binding trailing fold.

Locks the serialization the kernel's version-derivation must match BYTE-FOR-BYTE:
    measurement = HMAC(BM, b"umbra-encver-v1" || u32_le(author_id) || u32_le(version))
where BM is the version-independent block-chain measurement. The version is NOT
stored in clear; the kernel derives it by searching candidates against the
stamped measurement.
"""
import hmac, hashlib, struct
from protect_enclave import version_tag, ENCVER_LABEL


def test_encver_label_is_stable():
    assert ENCVER_LABEL == b"umbra-encver-v1"
    assert len(ENCVER_LABEL) == 15


def test_version_tag_matches_golden():
    bm = bytes(range(32))
    got = version_tag(bm, author_id=7, version=2)
    want = hmac.new(bm, ENCVER_LABEL + struct.pack("<II", 7, 2), hashlib.sha256).digest()
    assert got == want and len(got) == 32


def test_tag_differs_on_version_and_author():
    bm = bytes(range(32))
    base = version_tag(bm, 7, 2)
    assert version_tag(bm, 7, 1) != base
    assert version_tag(bm, 8, 2) != base
