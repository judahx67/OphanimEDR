"""Per-IOC verification against the BOTSv2 dataset.

For every IOC string in iocs.yaml (across all enabled scenarios and the
labeling.match_categories whitelist), report:

  * hits        total substring matches in `_raw` (lowercase) across the
                full dataset, IGNORING the scenario's current time_window
                — this is what reveals whether a window is too tight or
                too loose.
  * t_min/t_max wall-clock range of those hits (UTC ISO).
  * t_span_d   range in days.
  * top_st     top-3 sourcetypes by hit count (so we can see whether a
                signature only ever appears in one place, vs spreading
                across many — broad spread = likely false-positive IOC).

Output: CSV at `audit_iocs_hits.csv` next to this script + a short stdout
summary. The CSV is the artifact reviewed during defense prep.

Reads from the **unlabeled** corpus (datasets/botsv2_parquet/) so the
analysis is independent of the current labelling pass. Falls back to
datasets/botsv2_labeled/ if the unlabeled corpus isn't present (any row
in the labeled corpus still has `_raw`, so the substring search is the
same).

Runtime: ~5 min on the 188M-row corpus with polars lazy scan; can be
scoped down with --sourcetypes for iteration.

Usage:
    python audit_iocs.py                       # full corpus
    python audit_iocs.py --sourcetypes stream_http,suricata,pan_traffic
    python audit_iocs.py --top-st 5            # report top 5 sourcetypes per IOC
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import polars as pl
import yaml

ROOT = Path(__file__).resolve().parents[3].parents[0]
IOCS_PATH = Path(__file__).resolve().parent.parent / "iocs.yaml"

LABELED_DIR = Path("J:/THESIS-EDR/datasets/botsv2_labeled")
PARQUET_DIR = Path("J:/THESIS-EDR/datasets/botsv2_parquet")


def _fmt_ts(epoch: int | float | None) -> str:
    if epoch is None:
        return ""
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()


def load_iocs(path: Path) -> list[dict]:
    """Flatten enabled scenarios' whitelisted-category IOCs into one
    (scenario_id, category, value) record list. Skips blocklisted values
    but does NOT apply min_ioc_specificity — we want to evaluate every
    IOC, including short ones.
    """
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    label_cfg = cfg.get("labeling", {})
    categories = list(label_cfg.get("match_categories", []))
    blocklist = {p.lower() for p in label_cfg.get("blocklist_patterns", [])}

    out: list[dict] = []
    for sc in cfg.get("scenarios", []):
        if sc.get("enabled", True) is False:
            continue
        sid = sc["id"]
        win_start = int(sc["time_window"]["start"])
        win_end = int(sc["time_window"]["end"])
        for cat in categories:
            for v in sc.get(cat, []) or []:
                v_lower = str(v).strip().lower()
                if not v_lower or v_lower in blocklist:
                    continue
                out.append({
                    "scenario": sid,
                    "category": cat,
                    "value": v_lower,
                    "window_start": win_start,
                    "window_end": win_end,
                })
    return out


def discover_partitions(only: set[str] | None) -> list[Path]:
    """Pick the parquet root. Prefer the unlabeled corpus; fall back to
    labeled (labels don't affect _raw)."""
    root = PARQUET_DIR if PARQUET_DIR.exists() else LABELED_DIR
    if not root.exists():
        print(f"FATAL: no dataset at {PARQUET_DIR} or {LABELED_DIR}", file=sys.stderr)
        sys.exit(1)
    parts = sorted(root.glob("sourcetype=*"))
    if only is not None:
        parts = [p for p in parts if p.name.replace("sourcetype=", "") in only]
    print(f"Scanning {len(parts)} partitions under {root}")
    return parts


def audit_partition(pdir: Path, iocs: list[dict], top_st: int) -> dict[tuple[str, str, str], dict]:
    """One pass over a partition: for each IOC, accumulate hit count, t_min,
    t_max, and per-sourcetype hit count. Returns dict keyed by (scenario,
    category, value)."""
    sourcetype = pdir.name.replace("sourcetype=", "")
    pq_files = sorted(pdir.glob("*.parquet"))
    if not pq_files:
        return {}

    # One big lazy frame for the partition. Polars handles multi-file scan.
    lf = pl.scan_parquet(pq_files).select([
        pl.col("_raw").fill_null("").str.to_lowercase().alias("_raw_lc"),
        pl.col("_time"),
    ])

    # Build all hit expressions in a single collect — one pass over the data.
    aggs = []
    for i, ioc in enumerate(iocs):
        v = ioc["value"]
        hit = pl.col("_raw_lc").str.contains(v, literal=True)
        aggs.extend([
            hit.sum().alias(f"n_{i}"),
            pl.col("_time").filter(hit).min().alias(f"tmin_{i}"),
            pl.col("_time").filter(hit).max().alias(f"tmax_{i}"),
        ])

    try:
        row = lf.select(aggs).collect(streaming=True).row(0)
    except Exception as e:
        print(f"  WARN {sourcetype}: {e}", file=sys.stderr)
        return {}

    out: dict[tuple[str, str, str], dict] = {}
    per_field = 3  # n, tmin, tmax
    for i, ioc in enumerate(iocs):
        n = row[i * per_field]
        tmin = row[i * per_field + 1]
        tmax = row[i * per_field + 2]
        if not n:
            continue
        key = (ioc["scenario"], ioc["category"], ioc["value"])
        out[key] = {
            "n": int(n),
            "tmin": int(tmin) if tmin is not None else None,
            "tmax": int(tmax) if tmax is not None else None,
            "by_sourcetype": {sourcetype: int(n)},
        }
    return out


def merge(into: dict, src: dict) -> None:
    for k, v in src.items():
        cur = into.get(k)
        if cur is None:
            into[k] = dict(v)
            continue
        cur["n"] += v["n"]
        if v["tmin"] is not None:
            cur["tmin"] = v["tmin"] if cur["tmin"] is None else min(cur["tmin"], v["tmin"])
        if v["tmax"] is not None:
            cur["tmax"] = v["tmax"] if cur["tmax"] is None else max(cur["tmax"], v["tmax"])
        for st, c in v["by_sourcetype"].items():
            cur["by_sourcetype"][st] = cur["by_sourcetype"].get(st, 0) + c


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sourcetypes", default=None,
                    help="Comma-separated subset (e.g. stream_http,suricata)")
    ap.add_argument("--top-st", type=int, default=3,
                    help="Top-N sourcetypes per IOC to include in CSV")
    ap.add_argument("--out", default=None,
                    help="Output CSV path; default: audit_iocs_hits.csv next to this script")
    args = ap.parse_args()

    out_path = Path(args.out) if args.out else Path(__file__).resolve().parent / "audit_iocs_hits.csv"
    only = set(args.sourcetypes.split(",")) if args.sourcetypes else None

    iocs = load_iocs(IOCS_PATH)
    print(f"Auditing {len(iocs)} IOCs across {len({i['scenario'] for i in iocs})} scenarios")

    parts = discover_partitions(only)
    t0 = time.time()
    totals: dict[tuple[str, str, str], dict] = {}
    for pdir in parts:
        st = pdir.name.replace("sourcetype=", "")
        t1 = time.time()
        contribution = audit_partition(pdir, iocs, args.top_st)
        merge(totals, contribution)
        print(f"  {st:50s}  +{len(contribution):>4} ioc-hits   ({time.time()-t1:.1f}s)")

    print(f"\nTotal wall time: {(time.time()-t0)/60:.1f} min")
    print(f"IOCs with at least one hit: {len(totals)}")

    # Write CSV
    fieldnames = [
        "scenario", "category", "value", "hits",
        "t_min", "t_max", "t_span_days",
        "window_start", "window_end", "outside_window_pct",
        "top_sourcetypes",
    ]
    by_lookup = {(i["scenario"], i["category"], i["value"]): i for i in iocs}
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        rows_out = []
        for ioc in iocs:
            key = (ioc["scenario"], ioc["category"], ioc["value"])
            data = totals.get(key)
            if data is None:
                rows_out.append({
                    "scenario": ioc["scenario"],
                    "category": ioc["category"],
                    "value": ioc["value"],
                    "hits": 0,
                    "t_min": "",
                    "t_max": "",
                    "t_span_days": "",
                    "window_start": _fmt_ts(ioc["window_start"]),
                    "window_end": _fmt_ts(ioc["window_end"]),
                    "outside_window_pct": "",
                    "top_sourcetypes": "",
                })
                continue
            tmin, tmax = data["tmin"], data["tmax"]
            span = ((tmax - tmin) / 86400) if (tmin is not None and tmax is not None) else None
            top = sorted(data["by_sourcetype"].items(), key=lambda x: -x[1])[: args.top_st]
            rows_out.append({
                "scenario": ioc["scenario"],
                "category": ioc["category"],
                "value": ioc["value"],
                "hits": data["n"],
                "t_min": _fmt_ts(tmin),
                "t_max": _fmt_ts(tmax),
                "t_span_days": f"{span:.2f}" if span is not None else "",
                "window_start": _fmt_ts(ioc["window_start"]),
                "window_end": _fmt_ts(ioc["window_end"]),
                # NOTE: we don't know per-hit timestamps after this pass (only
                # min/max), so we can't compute outside-window-pct exactly here.
                # Left blank; downstream analysis on the CSV can compare t_min/t_max
                # vs window_start/window_end directly.
                "outside_window_pct": "",
                "top_sourcetypes": "; ".join(f"{st}={c}" for st, c in top),
            })
        # Stable sort: scenario, then by descending hits
        rows_out.sort(key=lambda r: (r["scenario"], -int(r["hits"] or 0)))
        w.writerows(rows_out)
    print(f"\nWrote CSV: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
