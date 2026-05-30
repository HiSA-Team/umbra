#!/usr/bin/env python3
"""
tools/aggregate_eval.py — Stage A Step 8.

Reads:
  eval_master.csv      — Umbra sweep 
  baseline_master.csv  — Native baseline 

Writes (default ./plot_csv/):
  runtime_plot.csv  — paper plot_runtime.png input
  boot_plot.csv     — paper boot_overhead_line_plot.png input
  switch_plot.csv   — paper switch_overhead_plot.png input

Schema:
  runtime_plot.csv: app, slot_bytes, cache_limit, speculation,
                   blob_size, native_cycles, umbra_cycles_mean,
                   overhead_x
  boot_plot.csv:   app, slot_bytes, cache_limit, speculation,
                   blob_size, size_bin_kb, boot_ns_mean,
                   boot_sec_mean, boot_total_mean
  switch_plot.csv: app, slot_bytes, cache_limit, speculation,
                   switch_mean_cycles, null_svc_cycles, overhead_x

Overhead semantics:
  runtime overhead_x = mean(umbra_runtime_cycles) / native_cycles
                       (1.0 = no overhead, 10.0 = 10× slowdown)
  switch  overhead_x = mean(switch_mean_cycles) / mean(null_svc_cycles)
                       (1.0 = same as bare TZ-round-trip)
  boot   no normalization yet — emit absolute cycles. Step 7b (Tock-side
         process-create instrumentation) is the planned divisor.

Reps are aggregated by mean within each (app, slot, cache, spec) cell.
PASS_FAIL=FAIL rows are excluded.

Usage:
    python tools/aggregate_eval.py \
      --eval-csv eval_master.csv \
      --baseline-csv baseline_master.csv \
      --out-dir plot_csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd  # type: ignore[import-not-found]


def hex_to_int(s):
    """Parse hex string '0xN' or decimal as int. Returns NaN on empty/None."""
    if s is None or (isinstance(s, float) and pd.isna(s)) or s == "":
        return float("nan")
    s = str(s).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        return float("nan")


def size_bin_kb(blob_size_bytes: int) -> int:
    """Bin blob_size into paper's 2/4/8/16/32/64 KB buckets.

    Bucket bounds chosen to match the paper's six panels in
    boot_overhead_line_plot.png. The smallest bin captures fib + dijkstra-64
    + the simple kernel benches; the largest captures cjpeg + statemate.
    Apps falling above 64 KB (none in our 13-app set) would go to the 64-bin
    by clamping.
    """
    bins = [(3 * 1024, 2), (5 * 1024, 4), (10 * 1024, 8),
            (20 * 1024, 16), (40 * 1024, 32)]
    for upper, lbl in bins:
        if blob_size_bytes < upper:
            return lbl
    return 64


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--eval-csv", required=True, type=Path)
    ap.add_argument("--baseline-csv", required=True, type=Path)
    ap.add_argument("--out-dir", default=Path("plot_csv"), type=Path)
    args = ap.parse_args()

    eval_df = pd.read_csv(args.eval_csv)
    base_df = pd.read_csv(args.baseline_csv)

    # ---- Filter PASS rows + parse hex cycle columns ----
    pass_df = eval_df[eval_df["pass_fail"] == "PASS"].copy()
    if len(pass_df) == 0:
        sys.exit("FATAL: no PASS rows in eval_master.csv")

    hex_cols = ["boot_ns_cycles", "boot_sec_cycles", "runtime_cycles",
                "switch_min_cycles", "switch_mean_cycles", "switch_max_cycles",
                "switch_count", "null_svc_cycles"]
    for c in hex_cols:
        pass_df[c] = pass_df[c].map(hex_to_int)

    # ---- Aggregate reps to mean per (app, slot, cache, spec) cell ----
    group_keys = ["app", "slot_bytes", "cache_limit", "speculation"]
    agg = pass_df.groupby(group_keys, as_index=False).agg(
        blob_size=("blob_size", "first"),
        boot_ns_mean=("boot_ns_cycles", "mean"),
        boot_sec_mean=("boot_sec_cycles", "mean"),
        runtime_mean=("runtime_cycles", "mean"),
        switch_mean=("switch_mean_cycles", "mean"),
        null_svc_mean=("null_svc_cycles", "mean"),
        n_reps=("rep_idx", "count"),
    )

    # ---- Merge baseline (native runtime per app) ----
    base = base_df.rename(columns={"native_cycles": "native_runtime"})[
        ["app", "native_runtime"]]
    agg = agg.merge(base, on="app", how="left")

    # PROXY for apps without a native baseline (Step 7c partial failure on
    # anagram + dijkstra + adpcm_dec): use the Umbra cycles at THAT
    # APP'S MAXIMALLY-FAVOURABLE existing config (largest SLOT × largest
    # CACHE × spec=on actually present in the CSV) as the divisor. This
    # INCLUDES Umbra's fixed TZ overhead, so the resulting overhead_x is
    # a CONSERVATIVE lower bound — the true native cycles would be
    # smaller, and real overhead would be larger. Per-app max because
    # not every app was swept at every config — the global max
    # (SLOT=8192, CACHE=16) may not exist for the missing apps (CACHE
    # tops out at 8 for them).
    proxy_mask = agg["native_runtime"].isna()
    if proxy_mask.any():
        missing = sorted(agg.loc[proxy_mask, "app"].unique())
        print(f"INFO: proxy baseline = per-app Umbra @ best (slot,cache,spec=1) for "
              f"{missing}", file=sys.stderr)
        for app in missing:
            # Filter cache >= 1 (cache=0 cells often return stub cycles
            # because cache-zero-mode + heavy bench = bench can't fit,
            # faults early, returns ~9000 cycles instead of completing).
            # Among real-completion cells (spec=1, cache>=1), the LARGEST
            # slot × LARGEST cache cell is the most-Umbra-favourable —
            # least swapping, lowest overhead — closest to "what native
            # would do plus Umbra TZ fixed cost". That's our proxy.
            real = agg[(agg["app"] == app)
                       & (agg["speculation"] == 1)
                       & (agg["cache_limit"] >= 1)]
            if len(real) == 0:
                print(f"  WARN: no usable rows for {app}; overhead_x stays NaN",
                      file=sys.stderr)
                continue
            # Highest (slot, cache) cell.
            best = real.sort_values(["slot_bytes", "cache_limit"],
                                    ascending=False).iloc[0]
            proxy_val = best["runtime_mean"]
            print(f"    {app}: proxy = {int(proxy_val):,} cycles "
                  f"(from slot={int(best['slot_bytes'])} "
                  f"cache={int(best['cache_limit'])} spec=1)",
                  file=sys.stderr)
            agg.loc[agg["app"] == app, "native_runtime"] = proxy_val
    agg["baseline_source"] = "native"
    agg.loc[proxy_mask, "baseline_source"] = "proxy_umbra_min"

    # ---- runtime_plot.csv ----
    runtime = agg.copy()
    runtime["overhead_x"] = runtime["runtime_mean"] / runtime["native_runtime"]
    runtime = runtime[["app", "slot_bytes", "cache_limit", "speculation",
                       "blob_size", "native_runtime", "runtime_mean",
                       "overhead_x", "baseline_source", "n_reps"]]

    # ---- boot_plot.csv ----
    boot = agg.copy()
    boot["size_bin_kb"] = boot["blob_size"].map(size_bin_kb)
    boot["boot_total_mean"] = boot["boot_ns_mean"] + boot["boot_sec_mean"]
    boot = boot[["app", "slot_bytes", "cache_limit", "speculation",
                 "blob_size", "size_bin_kb", "boot_ns_mean",
                 "boot_sec_mean", "boot_total_mean", "n_reps"]]

    # ---- switch_plot.csv ----
    sw = agg.copy()
    sw["overhead_x"] = sw["switch_mean"] / sw["null_svc_mean"]
    sw = sw[["app", "slot_bytes", "cache_limit", "speculation",
             "switch_mean", "null_svc_mean", "overhead_x", "n_reps"]]

    args.out_dir.mkdir(exist_ok=True, parents=True)
    runtime.to_csv(args.out_dir / "runtime_plot.csv", index=False)
    boot.to_csv(args.out_dir / "boot_plot.csv", index=False)
    sw.to_csv(args.out_dir / "switch_plot.csv", index=False)

    print(f"Wrote {len(runtime)} runtime rows → {args.out_dir/'runtime_plot.csv'}")
    print(f"Wrote {len(boot)}    boot rows    → {args.out_dir/'boot_plot.csv'}")
    print(f"Wrote {len(sw)}      switch rows  → {args.out_dir/'switch_plot.csv'}")

    print()
    print("---- runtime_plot.csv head ----")
    print(runtime.head(8).to_string(index=False))
    print()
    print("---- runtime overhead range per app ----")
    summary = runtime.groupby("app")["overhead_x"].agg(["min", "max"])
    print(summary.to_string())


if __name__ == "__main__":
    main()
