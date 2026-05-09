"""Phase 0: sanity-check the on-disk Parquet artifacts before re-running the pipeline.

Memory-conservative: one partition at a time, lazy scans, immediate flush of stdout.

Checks:
  1. botsv2_parquet/ row counts per partition (top 15) + total + schema sanity
  2. botsv2_labeled/ row counts per partition + per-scenario malicious counts.
     Anchors from docs/plans/botsv2-pipeline-log.md:
       total malicious : 2,150,080
       s200_webapp_attack  : 1,706,832
       s300_ransomware     :     4,709
       s400_taedonggang_apt:   438,539
  3. Spot-check 5 random malicious rows per scenario against iocs.yaml.

Run: .venv/Scripts/python phase0_sanity.py
"""
from __future__ import annotations

import gc
import json
import random
import sys
from pathlib import Path

import polars as pl
import yaml

PARQUET_DIR = Path("J:/THESIS-EDR/datasets/botsv2_parquet")
LABELED_DIR = Path("J:/THESIS-EDR/datasets/botsv2_labeled")
IOCS_PATH = Path(__file__).parent / "iocs.yaml"

ANCHORS = {
    "total_malicious": 2_150_080,
    "s200_webapp_attack": 1_706_832,
    "s300_ransomware": 4_709,
    "s400_taedonggang_apt": 438_539,
}


def log(msg: str = "") -> None:
    print(msg, flush=True)


def check_parquet() -> int:
    log("=" * 70)
    log("Check 1: botsv2_parquet/")
    log("=" * 70)
    parts = sorted(PARQUET_DIR.glob("sourcetype=*"))
    log(f"  partitions: {len(parts)}")
    counts: list[tuple[str, int]] = []
    for i, p in enumerate(parts):
        files = sorted(p.glob("*.parquet"))
        n = 0
        for f in files:
            n += pl.scan_parquet(f).select(pl.len()).collect().item()
        counts.append((p.name.replace("sourcetype=", ""), n))
        if (i + 1) % 20 == 0:
            log(f"    ...counted {i + 1}/{len(parts)} partitions")
    counts.sort(key=lambda x: -x[1])
    total = sum(n for _, n in counts)
    log(f"  total rows: {total:,}")
    log("  top 15 by row count:")
    for st, n in counts[:15]:
        log(f"    {st:40s} {n:>14,}")

    sample_files = list(parts[0].glob("*.parquet"))[:1]
    if sample_files:
        df = pl.read_parquet(sample_files[0], n_rows=1)
        log(f"  schema (sample from {parts[0].name}):")
        for c, d in zip(df.columns, df.dtypes):
            log(f"    {c}: {d}")
        ok_time = df["_time"].dtype == pl.Int64
        ok_meta = "_meta" not in df.columns
        log(f"  _time is Int64: {ok_time}   _meta absent: {ok_meta}")
    return total


def check_labeled() -> tuple[int, int, dict[str, int], list[tuple[str, int, int]]]:
    log("")
    log("=" * 70)
    log("Check 2: botsv2_labeled/")
    log("=" * 70)
    parts = sorted(LABELED_DIR.glob("sourcetype=*"))
    log(f"  partitions: {len(parts)}")

    total_rows = 0
    total_mal = 0
    per_scenario: dict[str, int] = {}
    per_st: list[tuple[str, int, int]] = []

    for i, p in enumerate(parts):
        f = p / "labeled.parquet"
        if not f.exists():
            continue
        # Lazy aggregation only — no full materialize.
        n = pl.scan_parquet(f).select(pl.len()).collect().item()
        mal = pl.scan_parquet(f).filter(pl.col("label") == 1).select(pl.len()).collect().item()
        total_rows += n
        total_mal += mal
        per_st.append((p.name.replace("sourcetype=", ""), n, mal))
        if mal > 0:
            sc_counts = (
                pl.scan_parquet(f)
                .filter(pl.col("label") == 1)
                .group_by("scenario")
                .agg(pl.len().alias("n"))
                .collect()
            )
            for sid, cnt in sc_counts.iter_rows():
                if sid is not None:
                    per_scenario[sid] = per_scenario.get(sid, 0) + int(cnt)
        if (i + 1) % 20 == 0:
            log(f"    ...processed {i + 1}/{len(parts)} partitions, total_mal so far {total_mal:,}")
        gc.collect()

    log(f"  total rows    : {total_rows:,}")
    log(f"  total malicious: {total_mal:,} ({100*total_mal/max(total_rows,1):.4f}%)")
    log("")
    log("  per-scenario malicious counts (vs anchors from pipeline log):")
    for sid, cnt in sorted(per_scenario.items()):
        anchor = ANCHORS.get(sid)
        if anchor is None:
            log(f"    {sid:30s} {cnt:>10,}   (no anchor)")
        else:
            delta = cnt - anchor
            mark = "OK" if delta == 0 else f"DELTA {delta:+,}"
            log(f"    {sid:30s} {cnt:>10,}   anchor {anchor:>10,}   {mark}")

    anchor_total = ANCHORS["total_malicious"]
    delta_total = total_mal - anchor_total
    log("")
    mark = "OK" if delta_total == 0 else f"DELTA {delta_total:+,}"
    log(f"  total mal vs anchor: {total_mal:,} vs {anchor_total:,}  {mark}")

    log("")
    log("  top 15 sourcetypes by malicious count:")
    per_st_sorted = sorted(per_st, key=lambda x: -x[2])
    for st, n, mal in per_st_sorted[:15]:
        if mal == 0:
            continue
        log(f"    {st:40s} rows={n:>12,}  mal={mal:>10,}  rate={100*mal/max(n,1):.4f}%")
    return total_rows, total_mal, per_scenario, per_st


def spot_check(per_scenario: dict[str, int]) -> None:
    log("")
    log("=" * 70)
    log("Check 3: spot-check 5 malicious rows per scenario for IOC presence in _raw")
    log("=" * 70)

    with open(IOCS_PATH, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    label_cfg = cfg.get("labeling", {})
    categories = set(label_cfg.get("match_categories", []))
    blocklist = {p.lower() for p in label_cfg.get("blocklist_patterns", [])}
    min_len = label_cfg.get("min_ioc_specificity", 8)
    scenario_iocs: dict[str, list[str]] = {}
    for sc in cfg.get("scenarios", []):
        if sc.get("enabled", True) is False:
            continue
        patterns = []
        for key in categories:
            for v in sc.get(key, []) or []:
                v = str(v).strip().lower()
                if v in blocklist:
                    continue
                if key in ("ips", "url_paths", "attack_signatures") or len(v) >= min_len:
                    patterns.append(v)
        scenario_iocs[sc["id"]] = sorted(set(patterns))

    rng = random.Random(42)
    parts = sorted(LABELED_DIR.glob("sourcetype=*"))

    for sid in sorted(per_scenario.keys()):
        log("")
        log(f"  --- {sid} ---")
        iocs = scenario_iocs.get(sid, [])
        log(f"  IOC patterns available: {len(iocs)}")

        # Reservoir-sample 5 rows across all partitions without materializing
        reservoir: list[tuple[str, dict]] = []
        seen = 0
        target = 5
        for p in parts:
            f = p / "labeled.parquet"
            if not f.exists():
                continue
            n_mal = (
                pl.scan_parquet(f)
                .filter((pl.col("label") == 1) & (pl.col("scenario") == sid))
                .select(pl.len())
                .collect()
                .item()
            )
            if n_mal == 0:
                continue
            df = (
                pl.scan_parquet(f)
                .filter((pl.col("label") == 1) & (pl.col("scenario") == sid))
                .select(["_time", "_raw"])
                .collect()
            )
            st = p.name.replace("sourcetype=", "")
            for row in df.iter_rows(named=True):
                seen += 1
                if len(reservoir) < target:
                    reservoir.append((st, row))
                else:
                    j = rng.randint(0, seen - 1)
                    if j < target:
                        reservoir[j] = (st, row)
            del df
            gc.collect()

        if not reservoir:
            log(f"    no rows found for {sid}")
            continue

        for st, row in reservoir:
            raw_lc = (row["_raw"] or "").lower()
            matched = [ioc for ioc in iocs if ioc in raw_lc]
            status = f"matched {len(matched)}" if matched else "NO IOC MATCH"
            preview = (row["_raw"] or "").replace("\n", " ")[:140]
            log(f"    [{st}] t={row['_time']} {status}: {matched[:3]}")
            log(f"      _raw: {preview}")
            if not matched:
                log("      WARN: malicious-labeled row but no IOC pattern in _raw")


def main() -> int:
    if not PARQUET_DIR.exists():
        log(f"FATAL: {PARQUET_DIR} missing")
        return 1
    if not LABELED_DIR.exists():
        log(f"FATAL: {LABELED_DIR} missing")
        return 1

    parquet_total = check_parquet()
    labeled_total, mal_total, per_scenario, per_st = check_labeled()

    log("")
    log("=" * 70)
    log("Cross-check: parquet total vs labeled total")
    log("=" * 70)
    log(f"  parquet : {parquet_total:,}")
    log(f"  labeled : {labeled_total:,}")
    log(f"  delta   : {labeled_total - parquet_total:+,}")

    spot_check(per_scenario)

    out = {
        "parquet_rows": parquet_total,
        "labeled_rows": labeled_total,
        "malicious_total": mal_total,
        "per_scenario": per_scenario,
        "anchors": ANCHORS,
        "per_sourcetype_top": [
            {"sourcetype": st, "rows": n, "malicious": mal}
            for st, n, mal in sorted(per_st, key=lambda x: -x[2])[:30]
        ],
    }
    out_path = Path(__file__).parent / "phase0_summary.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    log("")
    log(f"Wrote summary: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
