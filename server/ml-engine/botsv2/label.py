"""Phase 3: Label rows malicious (1) / benign (0) based on iocs.yaml.

For each scenario, build a single Aho-Corasick-backed pattern list from all
its string IOCs (domains, files, users, emails, signatures, url_paths, IPs,
processes, registry_keys, hostnames). A row is labeled malicious if its
_raw OR source OR host (concatenated, lowercased) contains any of that
scenario's IOCs AND its _time falls within the scenario's time_window.

Output adds two columns:
    label : Int8         (0=benign, 1=malicious)
    scenario : String    (scenario id when label=1, else null)

Writes labeled Parquet to botsv2_labeled/, mirroring partition layout.

Usage:
    python label.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import polars as pl
import yaml
from tqdm import tqdm

IN_DIR = Path("J:/THESIS-EDR/datasets/botsv2_parquet")
# Sibling-and-rename: write to _v2/ so a crash mid-run doesn't corrupt the
# existing labeled dataset. Caller renames _v2/ -> botsv2_labeled/ on success.
OUT_DIR = Path("J:/THESIS-EDR/datasets/botsv2_labeled_v2")
IOCS_PATH = Path(__file__).parent / "iocs.yaml"

# Weak-positive cohort rule REMOVED 2026-05-24. See iocs.yaml header for
# rationale. Pure IOC-substring labelling only.


def load_scenarios(path: Path) -> list[dict]:
    """Load iocs.yaml and flatten each scenario's string IOCs into one list.

    Honors labeling.match_categories (whitelist of IOC types) and
    labeling.blocklist_patterns (specific values to drop globally).
    """
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    label_cfg = cfg.get("labeling", {})
    min_len = label_cfg.get("min_ioc_specificity", 8)
    categories = set(label_cfg.get("match_categories", []))
    blocklist = {p.lower() for p in label_cfg.get("blocklist_patterns", [])}

    if not categories:
        raise ValueError("labeling.match_categories must be a non-empty list in iocs.yaml")

    scenarios = []
    for sc in cfg.get("scenarios", []):
        if sc.get("enabled", True) is False:
            continue
        patterns: list[str] = []
        for key in categories:
            for v in sc.get(key, []) or []:
                v = str(v).strip().lower()
                if v in blocklist:
                    continue
                # ips, url_paths, and attack_signatures get a length pass.
                # attack_signatures includes deliberately-chosen short strings
                # (e.g. ".crypt") so we must not filter them by length.
                if key in ("ips", "url_paths", "attack_signatures") or len(v) >= min_len:
                    patterns.append(v)
        seen = set()
        deduped = [p for p in patterns if not (p in seen or seen.add(p))]
        scenarios.append(
            {
                "id": sc["id"],
                "patterns": deduped,
                "start": int(sc["time_window"]["start"]),
                "end": int(sc["time_window"]["end"]),
            }
        )
    return scenarios


def _label_chunk(df: pl.DataFrame, scenarios: list[dict]) -> tuple[pl.DataFrame, dict]:
    """Label a single in-memory chunk via IOC substring match in _raw."""
    df = df.with_columns(
        pl.lit(0, dtype=pl.Int8).alias("label"),
        pl.lit(None, dtype=pl.String).alias("scenario"),
    )
    hit_counts: dict[str, int] = {}

    for sc in scenarios:
        if not sc["patterns"]:
            hit_counts[sc["id"]] = 0
            continue
        # Match against _raw only. host/source are scope metadata — including
        # them generates massive false positives (e.g. host "wrk-aturing" matches
        # every legit event from Amber's workstation if user "aturing" is in IOCs).
        haystack = pl.col("_raw").fill_null("").str.to_lowercase()
        match_expr = (
            haystack.str.contains_any(sc["patterns"])
            & (pl.col("_time") >= sc["start"])
            & (pl.col("_time") <= sc["end"])
            & (pl.col("label") == 0)
        )
        hits = df.filter(match_expr).height
        hit_counts[sc["id"]] = hits
        if hits > 0:
            df = df.with_columns(
                pl.when(match_expr).then(pl.lit(1, dtype=pl.Int8)).otherwise(pl.col("label")).alias("label"),
                pl.when(match_expr).then(pl.lit(sc["id"])).otherwise(pl.col("scenario")).alias("scenario"),
            )

    return df, hit_counts


def label_partition(parquet_files: list[Path], scenarios: list[dict]) -> tuple[pl.DataFrame, dict]:
    """Read a partition file-by-file (memory-safer for big partitions), label,
    then concat. Returns labeled DF + per-scenario hit counts."""
    chunks: list[pl.DataFrame] = []
    hit_counts: dict[str, int] = {}
    for f in parquet_files:
        chunk = pl.read_parquet(f)
        labeled, hits = _label_chunk(chunk, scenarios)
        chunks.append(labeled)
        for sid, c in hits.items():
            hit_counts[sid] = hit_counts.get(sid, 0) + c
    df = pl.concat(chunks, how="vertical_relaxed") if chunks else pl.DataFrame()
    return df, hit_counts


def main() -> int:
    if not IN_DIR.exists():
        print(f"FATAL: {IN_DIR} missing", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    scenarios = load_scenarios(IOCS_PATH)
    print(f"Loaded {len(scenarios)} scenarios:")
    for sc in scenarios:
        print(f"  {sc['id']}: {len(sc['patterns'])} patterns, window {sc['start']}->{sc['end']}")

    partitions = sorted(IN_DIR.glob("sourcetype=*"))
    print(f"\nLabeling {len(partitions)} partitions -> {OUT_DIR}")

    total_rows = 0
    total_malicious = 0
    per_st_stats: list[dict] = []
    per_scenario_total: dict[str, int] = {}
    started = time.time()

    pbar = tqdm(partitions, unit="part")
    for pdir in pbar:
        st_name = pdir.name.replace("sourcetype=", "")
        out_pdir = OUT_DIR / pdir.name
        out_pdir.mkdir(parents=True, exist_ok=True)
        out_file = out_pdir / "labeled.parquet"
        if out_file.exists():
            # Resume guard
            df = pl.read_parquet(out_file)
            mal = int((df["label"] == 1).sum())
            total_rows += df.height
            total_malicious += mal
            pbar.set_postfix(skip=st_name[:20], rows=f"{df.height:,}")
            continue

        files = sorted(pdir.glob("*.parquet"))
        if not files:
            continue

        df, hits = label_partition(files, scenarios)
        df.write_parquet(out_file, compression="zstd", compression_level=3)
        mal = int((df["label"] == 1).sum())
        total_rows += df.height
        total_malicious += mal
        for sid, c in hits.items():
            per_scenario_total[sid] = per_scenario_total.get(sid, 0) + c
        per_st_stats.append(
            {"sourcetype": st_name, "rows": df.height, "malicious": mal, "rate": mal / max(df.height, 1)}
        )
        pbar.set_postfix(rows=f"{df.height:,}", mal=f"{mal:,}", st=st_name[:20])

    elapsed = time.time() - started
    print(f"\nDone in {elapsed/60:.1f} min")
    print(f"  total rows: {total_rows:,}")
    print(f"  malicious : {total_malicious:,} ({100*total_malicious/max(total_rows,1):.4f}%)")
    print(f"\nPer-scenario hits (note: row counted at first matching scenario):")
    for sid, c in per_scenario_total.items():
        print(f"  {sid}: {c:,}")
    print(f"\nTop 15 sourcetypes by malicious count:")
    per_st_stats.sort(key=lambda r: r["malicious"], reverse=True)
    for r in per_st_stats[:15]:
        print(f"  {r['sourcetype']:40s} rows={r['rows']:>12,}  mal={r['malicious']:>8,}  rate={r['rate']*100:.4f}%")

    import json
    summary = {
        "total_rows": total_rows,
        "total_malicious": total_malicious,
        "positive_rate": total_malicious / max(total_rows, 1),
        "per_scenario": per_scenario_total,
        "per_sourcetype_top30": per_st_stats[:30],
        "elapsed_min": round(elapsed / 60, 2),
        "out_dir": str(OUT_DIR),
    }
    summary_path = OUT_DIR / "_label_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nWrote summary: {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
