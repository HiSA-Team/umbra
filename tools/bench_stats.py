#!/usr/bin/env python3
"""Aggregate the CSV produced by attest_update.py --csv / eval_attest.sh into the
numbers a paper table needs: n, mean, median, stdev, min, max per metric.
Cycle columns are converted to time at --cpu-hz (default 800 MHz N657).

Run: /opt/miniconda3/bin/python tools/bench_stats.py /tmp/umbra_attest_bench.csv
"""
import argparse
import csv
import statistics
import sys


def agg(label, vals, unit):
    if not vals:
        return
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    print(f"  {label:24s} n={len(vals):3d}  mean={statistics.mean(vals):10.3f}  "
          f"median={statistics.median(vals):10.3f}  stdev={sd:8.3f}  "
          f"min={min(vals):10.3f}  max={max(vals):10.3f}  {unit}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_file")
    ap.add_argument("--cpu-hz", type=float, default=800e6)
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.csv_file)))
    quotes = [r for r in rows if r["kind"] == "quote"]
    updates = [r for r in rows if r["kind"] == "update"]
    upd_ok = [r for r in updates if r["result"] == "OK"]

    def col(rs, name, scale=1.0):
        return [float(r[name]) * scale for r in rs if r.get(name)]

    ms_per_cyc = 1e3 / args.cpu_hz

    print(f"== {args.csv_file}: {len(quotes)} quote samples, {len(updates)} updates "
          f"({len(upd_ok)} OK)")
    if quotes:
        print("-- quote")
        agg("round-trip", col(quotes, "rtt_s", 1e3), "ms")
        agg("device generation", col(quotes, "gen_cyc", 1e6 / args.cpu_hz), "us")
    if updates:
        print("-- update (per phase)")
        agg("host tx (UART)", col(upd_ok, "tx_s", 1e3), "ms")
        agg("host wait-status", col(upd_ok, "resp_s", 1e3), "ms")
        for c in ("copy", "auth", "probe", "flash", "verify"):
            agg(f"device {c}", col(upd_ok, f"{c}_cyc", ms_per_cyc), "ms")
        agg("reboot-to-ready", col(upd_ok, "reboot_s"), "s")
        blob = col(upd_ok, "blob_len")
        if blob:
            print(f"  blob size: {int(blob[0])} B")
        bad = [r["result"] for r in updates if r["result"] != "OK"]
        if bad:
            print(f"  NON-OK updates: {bad}")


if __name__ == "__main__":
    main()
