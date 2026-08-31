#!/usr/bin/env python3
"""Remote attestation verifier + secure enclave updater for Umbra N657.

The verifier is TRUSTED: it holds MASTER_KEY (tools/master_key.bin) and re-derives
independent keys for quote verification and update-package signing. Talks the framed protocol
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
import re
import secrets
import statistics
import struct
import sys
import time
import zlib

SOF = 0xA5
QUOTE_MAGIC = 0x31545155   # "UQT1"
UPDATE_MAGIC = 0x31505555  # "UUP1"
QUOTE_LEN = 115
ATTEST_LABEL = b"umbra-attest-v1"
UPDATE_KEY_LABEL = b"umbra-update-key-v1"
# v2: pkg_tag preimage covers the FULL 48-byte UMBR header (blob[0:48]), not just
# header.hmac (blob[16:48]) — closes the unauthenticated trust_level/efbc_size/
# ess_blocks/reloc_count residue. Label version moves with the preimage layout.
PKG_LABEL = b"umbra-update-v2"

# NS relay command/response bytes (attest_relay.c)
CMD_QUOTE_REQ = 0x01
CMD_QUOTE_RESP = 0x81
CMD_UPDATE_REQ = 0x02
CMD_UPDATE_RESP = 0x82

# Update status codes (attest_imp.rs)
UPDATE_STATUS = {
    0xFFFFFF20: "ERR_NONCE", 0xFFFFFF21: "ERR_AUTH", 0xFFFFFF22: "ERR_VERIFY",
    0xFFFFFF23: "ERR_ROLLBACK", 0xFFFFFF24: "ERR_FLASH", 0xFFFFFF25: "ERR_BUSY",
    0xFFFFFFF6: "ERR_ARG",
}


def kattest(master):
    return hmac.new(master, ATTEST_LABEL, hashlib.sha256).digest()


def kupdate(master):
    return hmac.new(master, UPDATE_KEY_LABEL, hashlib.sha256).digest()


def send_frame(ser, cmd, payload):
    hdr = bytes([SOF, cmd]) + struct.pack("<H", len(payload))
    crc = struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
    ser.write(hdr + payload + crc)


def recv_frame(ser, soft=False):
    """Read one framed response. Returns (cmd, payload, preamble): preamble is the raw
    bytes skipped while resyncing on SOF — Secure-side ASCII log lines, including the
    `[UMBRA-BENCH]` telemetry the bench modes parse. With soft=True a timeout returns
    (None, None, preamble) instead of exiting (used while polling across a reboot)."""
    pre = bytearray()
    while True:
        b = ser.read(1)
        if not b:
            if soft:
                return None, None, bytes(pre)
            sys.exit("timeout waiting for response frame (is the board in the relay loop?)")
        if b[0] == SOF:
            break
        pre.append(b[0])
    hdr = ser.read(3)
    if len(hdr) < 3:
        if soft:
            return None, None, bytes(pre)
        sys.exit("timeout inside response frame header")
    cmd = hdr[0]
    ln = struct.unpack("<H", hdr[1:3])[0]
    payload = ser.read(ln)
    crcb = ser.read(4)
    if len(payload) < ln or len(crcb) < 4:
        if soft:
            return None, None, bytes(pre)
        sys.exit("timeout inside response frame body")
    crc = struct.unpack("<I", crcb)[0]
    if zlib.crc32(payload) & 0xFFFFFFFF != crc:
        if soft:
            return None, None, bytes(pre)
        sys.exit("CRC mismatch on response frame")
    return cmd, payload, bytes(pre)


def bench_cycles(pre, pattern):
    """Extract an 8-digit-hex cycle count printed by the Secure side (or None)."""
    m = re.search(pattern, pre.decode("ascii", "replace"))
    return int(m.group(1), 16) if m else None


def print_stats(label, samples, unit, scale=1.0):
    if not samples:
        print(f"  {label}: no samples")
        return
    vals = [s * scale for s in samples]
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    print(f"  {label}: n={len(vals)} mean={statistics.mean(vals):.3f} "
          f"median={statistics.median(vals):.3f} stdev={sd:.3f} "
          f"min={min(vals):.3f} max={max(vals):.3f} {unit}")


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
    if not ok_tag:
        # A tag failure on a board that boots cleanly is almost always a key
        # mismatch, not an attack, and it mimics a stale boot image closely
        # enough to cost an afternoon. `cargo xtask flash` reverts the four key
        # files after a session unless UMBRA_KEEP_MASTER_KEY is set, so the
        # verifier can end up reading a different key than the one compiled into
        # the firmware just flashed. Say so here, where it is first seen.
        print("               ^ the device computed this tag with a DIFFERENT key than")
        print("                 tools/master_key.bin. Check the four copies agree:")
        print("                     python tools/test_attestation_guard.py")
        print("                 and re-flash with UMBRA_KEEP_MASTER_KEY=1 exported.")
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


def build_pkg(nonce, author_id, version, blob, master, key=None):
    if len(blob) < 48:
        sys.exit("blob too short to contain a UMBR header")
    header = blob[0:48]
    pre = PKG_LABEL + bytes(nonce) + struct.pack("<III", author_id, version, len(blob)) + header
    tag = hmac.new(key if key is not None else kupdate(master), pre, hashlib.sha256).digest()
    return (struct.pack("<I", UPDATE_MAGIC) + bytes(nonce)
            + struct.pack("<III", author_id, version, len(blob)) + blob + tag)


# ---------------------------------------------------------------------------
# Adversarial harness (gap-4): each named attack is DEFENDED iff the device (or,
# for stale-quote, the host verifier) rejects it with the expected status. Run
# --count times; a single systematic breach is then n/N-visible.
# ---------------------------------------------------------------------------
ERR_NONCE, ERR_AUTH, ERR_VERIFY, ERR_ROLLBACK, ERR_ARG = (
    0xFFFFFF20, 0xFFFFFF21, 0xFFFFFF22, 0xFFFFFF23, 0xFFFFFFF6)


def _quote(ser):
    """Request a quote with a fresh nonce; return (fields|None, nonce, raw)."""
    nonce = secrets.token_bytes(16)
    send_frame(ser, CMD_QUOTE_REQ, nonce)
    cmd, payload, _ = recv_frame(ser)
    if cmd != CMD_QUOTE_RESP or len(payload) != QUOTE_LEN:
        return None, nonce, payload
    return parse_quote(payload), nonce, payload


def _update(ser, pkg):
    send_frame(ser, CMD_UPDATE_REQ, bytes(pkg))
    cmd, payload, _ = recv_frame(ser)
    return struct.unpack("<I", payload[:4])[0] if payload and len(payload) >= 4 else None


def _dummy_blob():
    # 48-byte fake UMBR header; enough to be well-formed for the paths that reject
    # BEFORE any flash write (nonce/tag), which never inspect the header contents.
    return bytes(48)


# name -> (mutating?, {accepted status codes}, human label)
ATTACKS = {
    "no-quote":    (False, {ERR_NONCE}, "update with no armed nonce"),
    "replay":      (False, {ERR_NONCE}, "re-use a superseded (stale) nonce"),
    "wrong-key":   (False, {ERR_AUTH}, "correct nonce, tag signed with wrong key"),
    "malformed":   (False, {ERR_ARG}, "truncated / oversized package"),
    "stale-quote": (False, {ERR_NONCE}, "verifier freshness: old quote vs new nonce"),
    "tamper":      (True, {ERR_VERIFY}, "valid tag, flipped code byte (measurement fails)"),
    "header-flip": (True, {ERR_AUTH}, "flip trust_level after signing (tag covers blob[0:48])"),
    "downgrade":   (True, {ERR_ROLLBACK, ERR_VERIFY}, "install version <= active"),
}


def _one_attack(ser, master, name, blob, version, author_id):
    """Run one attack attempt; return (defended: bool, detail: str)."""
    if name == "no-quote":
        st = _update(ser, build_pkg(secrets.token_bytes(16), author_id, 99, _dummy_blob(), master))
        return st == ERR_NONCE, f"status=0x{st:08x}"
    if name == "replay":
        _q1, n1, _ = _quote(ser)          # arms n1
        _quote(ser)                        # arms n2, superseding n1
        st = _update(ser, build_pkg(n1, author_id, 99, _dummy_blob(), master))  # replay n1
        return st == ERR_NONCE, f"status=0x{st:08x}"
    if name == "wrong-key":
        _q, n, _ = _quote(ser)
        st = _update(ser, build_pkg(n, author_id, 99, _dummy_blob(), master,
                                    key=secrets.token_bytes(32)))  # forged tag
        return st == ERR_AUTH, f"status=0x{st:08x}"
    if name == "malformed":
        _q, _n, _ = _quote(ser)
        st = _update(ser, secrets.token_bytes(64))  # < 112 B front-gate reject
        return st == ERR_ARG, f"status=0x{st:08x}"
    if name == "stale-quote":
        _q1, n1, raw1 = _quote(ser)        # capture quote for n1
        _q2, n2, _ = _quote(ser)           # fresh nonce n2
        # A replayed quote is only "fresh" if its nonce matches the challenge we just
        # issued. Verifier enforces that; the device is not consulted here.
        fresh = hmac.compare_digest(raw1[4:20], n2)
        return not fresh, f"replayed-quote-fresh={fresh}"
    if name == "tamper":
        _q, n, _ = _quote(ser)
        pkg = bytearray(build_pkg(n, author_id, version, blob, master))
        pkg[32 + 60] ^= 0xFF               # flip a code byte (past the 48-B header)
        st = _update(ser, pkg)
        return st == ERR_VERIFY, f"status=0x{st:08x}"
    if name == "header-flip":
        # v2 regression: trust_level (blob[4]) is now inside the pkg_tag preimage,
        # so a post-signing flip must die at authentication (ERR_AUTH), before any
        # flash write. Under the v1 preimage (blob[16:48] only) this byte was
        # silently accepted.
        _q, n, _ = _quote(ser)
        pkg = bytearray(build_pkg(n, author_id, version, blob, master))
        pkg[32 + 4] ^= 0x01                # trust_level, formerly unauthenticated
        st = _update(ser, pkg)
        return st == ERR_AUTH, f"status=0x{st:08x}"
    if name == "downgrade":
        _q, n, _ = _quote(ser)
        st = _update(ser, build_pkg(n, author_id, version, blob, master))
        return st in (ERR_ROLLBACK, ERR_VERIFY), f"status=0x{st:08x}"
    raise ValueError(name)


def run_attack(ser, master, name, count, blob, version, author_id):
    mut, accept, label = ATTACKS[name]
    accept_str = "/".join(UPDATE_STATUS.get(c, hex(c)) for c in sorted(accept))
    n = 1 if mut else count   # mutating attacks touch the inactive slot; run once
    defended, last = 0, ""
    for _ in range(n):
        ok, last = _one_attack(ser, master, name, blob, version, author_id)
        defended += ok
    verdict = "DEFENDED" if defended == n else "BREACH"
    print(f"  [{verdict}] {name:11s} {defended}/{n}  expect={accept_str:20s} "
          f"({label}; last {last})")
    return defended == n


def csv_append(path, row):
    if not path:
        return
    new = not os.path.exists(path)
    with open(path, "a") as fh:
        if new:
            fh.write("kind,i,blob_len,version,rtt_s,gen_cyc,tx_s,resp_s,"
                     "copy_cyc,auth_cyc,probe_cyc,flash_cyc,verify_cyc,reboot_s,result\n")
        fh.write(",".join("" if v is None else str(v) for v in row) + "\n")


def bench_quote(ser, master, n, cpu_hz, csv_path):
    """N quote round-trips: host wall-clock RTT + device-side generation cycles.
    NOTE: the RTT includes the device's ~30-char telemetry print (~3 ms at 115200);
    the cycle count is the print-free generation cost (gather + HW HMAC)."""
    print(f"[*] quote bench: {n} iterations...")
    rtts, cycs, fails = [], [], {}
    key = kattest(master)
    for i in range(n):
        nonce = secrets.token_bytes(16)
        t0 = time.perf_counter()
        send_frame(ser, CMD_QUOTE_REQ, nonce)
        cmd, payload, pre = recv_frame(ser)
        rtt = time.perf_counter() - t0
        # Classify failures so a systematic one (e.g. rotated master_key -> every tag
        # FAILs) is self-evident instead of an opaque count.
        if cmd != CMD_QUOTE_RESP or len(payload) != QUOTE_LEN:
            st = struct.unpack("<I", payload[:4])[0] if payload and len(payload) >= 4 else 0
            why = f"error frame cmd=0x{cmd:x} status=0x{st:08x}"
        elif not hmac.compare_digest(
                hmac.new(key, payload[:83], hashlib.sha256).digest(), payload[83:115]):
            why = "tag FAIL (master_key mismatch? see UMBRA_KEEP_MASTER_KEY)"
        elif not hmac.compare_digest(nonce, payload[4:20]):
            why = "nonce mismatch (stale/replayed quote)"
        else:
            why = None
        if why is not None:
            fails[why] = fails.get(why, 0) + 1
            continue
        cyc = bench_cycles(pre, r"quote cyc=([0-9A-F]{8})")
        rtts.append(rtt)
        if cyc is not None:
            cycs.append(cyc)
        csv_append(csv_path, ["quote", i, None, None, f"{rtt:.6f}", cyc, None, None,
                              None, None, None, None, None, None, "OK"])
    print_stats("round-trip", rtts, "ms", 1e3)
    print_stats("device gen", cycs, "us", 1e6 / cpu_hz)
    for why, cnt in fails.items():
        print(f"  FAILED {cnt}/{n}: {why}")
    return not fails


def wait_ready(ser, master, timeout, expect_version):
    """Poll quotes until the rebooted device answers with a valid one. Returns the
    seconds elapsed, or None on timeout. Safe against the boot window: the relay
    drains stale RX at start and every poll uses a fresh nonce + soft timeout."""
    key = kattest(master)
    t0 = time.perf_counter()
    old_to = ser.timeout
    ser.timeout = 2.0
    try:
        while time.perf_counter() - t0 < timeout:
            ser.reset_input_buffer()
            nonce = secrets.token_bytes(16)
            send_frame(ser, CMD_QUOTE_REQ, nonce)
            cmd, payload, _ = recv_frame(ser, soft=True)
            if (cmd == CMD_QUOTE_RESP and payload is not None and len(payload) == QUOTE_LEN
                    and hmac.compare_digest(
                        hmac.new(key, payload[:83], hashlib.sha256).digest(), payload[83:115])
                    and hmac.compare_digest(nonce, payload[4:20])):
                ver = struct.unpack_from("<I", payload, 61)[0]
                if expect_version is None or ver >= expect_version:
                    return time.perf_counter() - t0
            time.sleep(0.5)
    finally:
        ser.timeout = old_to
    return None


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
    ap.add_argument("--bench-quote", type=int, metavar="N",
                    help="benchmark: N quote round-trips, print latency stats, then exit")
    ap.add_argument("--attack", choices=sorted(ATTACKS) + ["all"],
                    help="adversarial harness: run one named attack --count times and "
                         "report defended/total (tamper/downgrade need --update-blob)")
    ap.add_argument("--count", type=int, default=20, help="attack repetitions (default 20)")
    ap.add_argument("--bench", action="store_true",
                    help="time the update end-to-end (tx / device phases / reboot-to-ready)")
    ap.add_argument("--csv", help="append per-sample bench rows to this CSV file")
    ap.add_argument("--cpu-hz", type=float, default=800e6,
                    help="CPU clock for cycle->time conversion (default 800 MHz)")
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

    if args.bench_quote:
        sys.exit(0 if bench_quote(ser, master, args.bench_quote, args.cpu_hz, args.csv) else 1)

    if args.attack:
        # "all" runs the whole adversarial suite in one pass. Order matters: the
        # non-mutating attacks run first, so a mutating one cannot leave the device
        # rebooted into a different version underneath them.
        names = (sorted(ATTACKS, key=lambda n: ATTACKS[n][0])
                 if args.attack == "all" else [args.attack])
        blob = open(args.update_blob, "rb").read() if args.update_blob else None
        results = []
        for name in names:
            mut, _, _ = ATTACKS[name]
            if mut and blob is None:
                if args.attack == "all":
                    print(f"  {name:<12} SKIPPED (needs --update-blob)")
                    continue
                sys.exit(f"attack '{name}' needs --update-blob (a valid signed enclave)")
            if len(names) > 1:
                print(f"\n=== {name} — {ATTACKS[name][2]} ===")
            results.append((name, run_attack(ser, master, name, args.count, blob,
                                             args.version or 1, args.author_id)))
        if len(results) > 1:
            bad = [n for n, ok in results if not ok]
            print(f"\n[*] {len(results) - len(bad)}/{len(results)} defended"
                  + (f" — FAILED: {', '.join(bad)}" if bad else ""))
        sys.exit(0 if all(ok for _, ok in results) else 1)

    f = None
    if args.no_quote:
        print("[*] --no-quote: sending update with a random (unarmed) nonce...")
    else:
        nonce = secrets.token_bytes(16)
        print("[*] requesting quote...")
        send_frame(ser, CMD_QUOTE_REQ, nonce)
        cmd, payload, _ = recv_frame(ser)
        if cmd != CMD_QUOTE_RESP or len(payload) != QUOTE_LEN:
            st = struct.unpack("<I", payload[:4])[0] if len(payload) >= 4 else 0
            sys.exit(f"quote error: cmd=0x{cmd:x} status=0x{st:08x}")
        f, ok = verify_quote(payload, master, nonce, args.expect_version)
        if not ok and not args.update_blob:
            sys.exit(1)

    if args.update_blob:
        blob = open(args.update_blob, "rb").read()
        ver = args.version if args.version is not None else ((f["version"] + 1) if f else 3)
        upd_nonce = f["nonce"] if f else secrets.token_bytes(16)
        pkg = bytearray(build_pkg(upd_nonce, args.author_id, ver, blob, master))
        if args.tamper:
            # Corrupt a CODE byte (package prefix is 32 B, then blob: 48-B header then
            # code). pkg_tag covers blob[0:48] (the full header) but not the code, so
            # authentication still passes but the re-verify-from-flash measurement fails.
            ti = 32 + 60
            pkg[ti] ^= 0xFF
            print(f"[*] --tamper: flipped code byte at package offset {ti} (expect ERR_VERIFY)")
        print(f"[*] sending update ({len(blob)} byte blob, version {ver})...")
        t0 = time.perf_counter()
        send_frame(ser, CMD_UPDATE_REQ, bytes(pkg))
        ser.flush()  # drain the OS/USB buffer so t_tx approximates the real UART TX time
        t_tx = time.perf_counter() - t0
        cmd, payload, pre = recv_frame(ser)
        t_resp = time.perf_counter() - t0 - t_tx
        st = struct.unpack("<I", payload[:4])[0]
        name = "OK" if st == 0 else UPDATE_STATUS.get(st, "REJECTED")
        print(f"[*] update status: 0x{st:08x} ({name})")
        phases = {k: bench_cycles(pre, rf"{k}=([0-9A-F]{{8}})")
                  for k in ("copy", "auth", "probe", "flash", "verify")}
        t_reboot = None
        if args.bench:
            us = 1e6 / args.cpu_hz
            print(f"  tx={t_tx * 1e3:.1f} ms  resp={t_resp * 1e3:.1f} ms")
            for k, v in phases.items():
                print(f"  {k:6s}: " + (f"{v} cyc = {v * us / 1e3:.2f} ms" if v is not None else "n/a"))
            if st == 0:
                print("[*] waiting for reboot-to-ready (device re-creates + runs the enclave)...")
                t_reboot = wait_ready(ser, master, timeout=120.0, expect_version=ver)
                print(f"  reboot-to-ready: " +
                      (f"{t_reboot:.2f} s (version >= {ver} confirmed)" if t_reboot is not None
                       else "TIMEOUT"))
            csv_append(args.csv, ["update", 0, len(blob), ver, None, None,
                                  f"{t_tx:.6f}", f"{t_resp:.6f}",
                                  phases["copy"], phases["auth"], phases["probe"],
                                  phases["flash"], phases["verify"],
                                  f"{t_reboot:.3f}" if t_reboot is not None else None,
                                  "OK" if st == 0 else f"0x{st:08x}"])
        elif st == 0:
            print("[*] status 0 means: written to the inactive slot and RE-VERIFIED FROM"
                  " FLASH at a strictly higher version.")
            print("    It does NOT mean the new image is running. Activation happens at the"
                  " next create(0), which")
            print("    only the auto-select host performs — the NS host must have been built"
                  " with UMBRA_CREATE_BEST_SLOT=1")
            print("    (see tools/eval_attest.sh). Built without it, main.c calls"
                  " umbra_enclave_create(<fixed addr>), so the")
            print("    new slot is authenticated and then never selected: the quote keeps"
                  " reporting the old version and an")
            print("    IDENTICAL boot measurement, with nothing having failed.")
            print("[*] device is rebooting; re-run with --expect-version <new> in a few"
                  " seconds to confirm.")
        fail = st != 0 or (args.bench and st == 0 and t_reboot is None)
        sys.exit(2 if fail else 0)


if __name__ == "__main__":
    main()
