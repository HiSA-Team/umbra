#!/usr/bin/env python3
"""Remote attestation verifier + secure enclave updater for Umbra N657.

The verifier is TRUSTED: it holds MASTER_KEY (tools/master_key.bin) and re-derives
the attestation key K_attest = HMAC(MASTER_KEY, "umbra-attest-v1") to check quote
tags and to sign update packages. Talks the framed protocol
    [SOF 0xA5][cmd u8][len u16 LE][payload][crc32 LE]
to the Non-Secure relay over the ST-Link VCP.

Byte layout is pinned by tools/test_attestation_guard.py (Python <-> Rust parity).

Usage:
  python tools/attest_update.py --port /dev/cu.usbmodem211203 --expect-version 2
  python tools/attest_update.py --update-blob v3.bin --version 3
"""
import argparse
import hashlib
import hmac
import os
import random
import struct
import sys
import zlib

SOF = 0xA5
QUOTE_MAGIC = 0x31545155   # "UQT1"
UPDATE_MAGIC = 0x31505555  # "UUP1"
QUOTE_LEN = 115
ATTEST_LABEL = b"umbra-attest-v1"
PKG_LABEL = b"umbra-update-v1"

# NS relay command/response bytes (attest_relay.c)
CMD_QUOTE_REQ = 0x01
CMD_QUOTE_RESP = 0x81
CMD_UPDATE_REQ = 0x02
CMD_UPDATE_RESP = 0x82


def kattest(master):
    return hmac.new(master, ATTEST_LABEL, hashlib.sha256).digest()


def send_frame(ser, cmd, payload):
    hdr = bytes([SOF, cmd]) + struct.pack("<H", len(payload))
    crc = struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
    ser.write(hdr + payload + crc)


def recv_frame(ser):
    # Resync on SOF.
    while True:
        b = ser.read(1)
        if not b:
            sys.exit("timeout waiting for response frame (is the board in the relay loop?)")
        if b[0] == SOF:
            break
    cmd = ser.read(1)[0]
    ln = struct.unpack("<H", ser.read(2))[0]
    payload = ser.read(ln)
    crc = struct.unpack("<I", ser.read(4))[0]
    if zlib.crc32(payload) & 0xFFFFFFFF != crc:
        sys.exit("CRC mismatch on response frame")
    return cmd, payload


def parse_quote(q):
    if len(q) != QUOTE_LEN:
        sys.exit(f"quote length {len(q)} != {QUOTE_LEN}")
    if struct.unpack_from("<I", q, 0)[0] != QUOTE_MAGIC:
        sys.exit("bad quote magic")
    return {
        "nonce": q[4:20],
        "enclave_id": struct.unpack_from("<I", q, 20)[0],
        "status": q[24],
        "bm": q[25:57],
        "author_id": struct.unpack_from("<I", q, 57)[0],
        "version": struct.unpack_from("<I", q, 61)[0],
        "floor": struct.unpack_from("<I", q, 65)[0],
        "anchor_gen": struct.unpack_from("<I", q, 69)[0],
        "restore": q[73],
        "reset_cause": struct.unpack_from("<I", q, 74)[0],
        "hdpl": q[78],
        "flags": struct.unpack_from("<I", q, 79)[0],
        "tag": q[83:115],
    }


_RESTORE = {0: "none", 1: "Resume", 2: "ColdGenesis", 3: "Reject"}


def verify_quote(q, master, nonce, expect_version):
    f = parse_quote(q)
    tag = hmac.new(kattest(master), q[:83], hashlib.sha256).digest()
    ok_tag = hmac.compare_digest(tag, f["tag"])
    ok_nonce = hmac.compare_digest(bytes(nonce), f["nonce"])
    print(f"  tag        : {'OK' if ok_tag else 'FAIL'}")
    print(f"  nonce      : {'fresh' if ok_nonce else 'STALE/REPLAY'}")
    print(f"  enclave_id : {f['enclave_id']}  status={f['status']}")
    print(f"  bm         : {f['bm'].hex()}")
    print(f"  version    : {f['version']}  floor={f['floor']}  author={f['author_id']}")
    print(f"  anchor_gen : {f['anchor_gen']}  restore={_RESTORE.get(f['restore'], f['restore'])}")
    print(f"  reset      : 0x{f['reset_cause']:08x}  hdpl=0x{f['hdpl']:02x}  flags=0x{f['flags']:x}")
    verdict = ok_tag and ok_nonce
    # RCC_RSR PORRSTF is bit 23 on N657: a POR cold-wiped the backup domain, so the
    # anti-rollback floor / state anchor were fail-open this boot.
    if f["reset_cause"] & (1 << 23):
        print("  WARNING: POR reset — anti-rollback floor/anchor were cold (fail-open window)")
    if f["restore"] == 3:
        print("  WARNING: last state restore was REJECTED (runtime-state rollback attempt)")
    if expect_version is not None and f["version"] < expect_version:
        print(f"  FAIL: version {f['version']} < expected {expect_version} (wrong/rolled-back enclave)")
        verdict = False
    print(f"  VERDICT    : {'TRUSTED' if verdict else 'UNTRUSTED'}")
    return f, verdict


def build_pkg(nonce, author_id, version, blob, master):
    if len(blob) < 48:
        sys.exit("blob too short to contain a UMBR header")
    header_hmac = blob[16:48]
    pre = PKG_LABEL + bytes(nonce) + struct.pack("<III", author_id, version, len(blob)) + header_hmac
    tag = hmac.new(kattest(master), pre, hashlib.sha256).digest()
    return (struct.pack("<I", UPDATE_MAGIC) + bytes(nonce)
            + struct.pack("<III", author_id, version, len(blob)) + blob + tag)


def main():
    ap = argparse.ArgumentParser(description="Umbra N657 remote attestation + secure update")
    ap.add_argument("--port", default="/dev/cu.usbmodem211203")
    ap.add_argument("--master", default=os.path.join(os.path.dirname(__file__), "master_key.bin"))
    ap.add_argument("--expect-version", type=int, default=None,
                    help="fail the verdict if the reported enclave version is below this")
    ap.add_argument("--update-blob", help="protect_enclave.py output blob to install")
    ap.add_argument("--author-id", type=int, default=1)
    ap.add_argument("--version", type=int, default=None,
                    help="declared version for the update (default: reported+1)")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--no-quote", action="store_true",
                    help="negative test: send the update with a random nonce and NO preceding "
                         "quote (the device nonce is unarmed) -> expect ERR_NONCE")
    ap.add_argument("--tamper", action="store_true",
                    help="negative test: corrupt a code byte after signing (pkg_tag still valid, "
                         "but the on-flash measurement fails) -> expect ERR_VERIFY")
    args = ap.parse_args()

    try:
        import serial  # noqa: PLC0415 — optional dep; only needed when talking to the board
    except ImportError:
        sys.exit("pyserial not installed: /opt/miniconda3/bin/pip install pyserial")

    master = open(args.master, "rb").read()
    if len(master) != 32:
        sys.exit(f"master key must be 32 bytes, got {len(master)}")
    ser = serial.Serial(args.port, 115200, timeout=args.timeout)
    ser.reset_input_buffer()  # drop any stale boot-log / prior-response bytes

    f = None
    if args.no_quote:
        print("[*] --no-quote: sending update with a random (unarmed) nonce...")
    else:
        nonce = bytes(random.getrandbits(8) for _ in range(16))
        print("[*] requesting quote...")
        send_frame(ser, CMD_QUOTE_REQ, nonce)
        cmd, payload = recv_frame(ser)
        if cmd != CMD_QUOTE_RESP or len(payload) != QUOTE_LEN:
            st = struct.unpack("<I", payload[:4])[0] if len(payload) >= 4 else 0
            sys.exit(f"quote error: cmd=0x{cmd:x} status=0x{st:08x}")
        f, ok = verify_quote(payload, master, nonce, args.expect_version)
        if not ok and not args.update_blob:
            sys.exit(1)

    if args.update_blob:
        blob = open(args.update_blob, "rb").read()
        ver = args.version if args.version is not None else ((f["version"] + 1) if f else 3)
        upd_nonce = f["nonce"] if f else bytes(random.getrandbits(8) for _ in range(16))
        pkg = bytearray(build_pkg(upd_nonce, args.author_id, ver, blob, master))
        if args.tamper:
            # Corrupt a CODE byte (package prefix is 32 B, then blob: 48-B header then
            # code). pkg_tag covers only blob[16:48] (header.hmac), so authentication
            # still passes but the re-verify-from-flash measurement fails.
            ti = 32 + 60
            pkg[ti] ^= 0xFF
            print(f"[*] --tamper: flipped code byte at package offset {ti} (expect ERR_VERIFY)")
        print(f"[*] sending update ({len(blob)} byte blob, version {ver})...")
        send_frame(ser, CMD_UPDATE_REQ, bytes(pkg))
        cmd, payload = recv_frame(ser)
        st = struct.unpack("<I", payload[:4])[0]
        print(f"[*] update status: 0x{st:08x} ({'OK' if st == 0 else 'REJECTED'})")
        if st == 0:
            print("[*] device is rebooting into the new version (no manual reset needed);")
            print("    re-run with --expect-version <new> in a few seconds to confirm.")
        sys.exit(0 if st == 0 else 2)


if __name__ == "__main__":
    main()
