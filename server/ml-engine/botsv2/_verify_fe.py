"""Sanity-check the FE output: malicious-row preservation across the full
featured Parquet (not just this run's stats).

Compares against the labeling anchor:
    total malicious : 2,150,080
    s200            : 1,706,832
    s300            :     4,709
    s400            :   438,539
"""
from __future__ import annotations
import json
from pathlib import Path
import polars as pl

FEAT = Path("J:/THESIS-EDR/datasets/botsv2_features_v2")

ANCHORS = {
    "total_malicious": 2_150_080,
    "s200_webapp_attack": 1_706_832,
    "s300_ransomware": 4_709,
    "s400_taedonggang_apt": 438_539,
}


def main():
    parts = sorted(FEAT.glob("sourcetype=*"))
    total_rows = 0
    total_mal = 0
    per_scenario: dict[str, int] = {}
    triple_filled = 0
    triple_filled_among_mal = 0

    for p in parts:
        f = p / "featured.parquet"
        if not f.exists():
            continue
        n = pl.scan_parquet(f).select(pl.len()).collect().item()
        mal = pl.scan_parquet(f).filter(pl.col("label") == 1).select(pl.len()).collect().item()
        tf = (
            pl.scan_parquet(f)
            .filter(
                pl.col("subject_type").is_not_null()
                & pl.col("object_type").is_not_null()
                & pl.col("edge_type").is_not_null()
            )
            .select(pl.len())
            .collect()
            .item()
        )
        tfm = (
            pl.scan_parquet(f)
            .filter(
                (pl.col("label") == 1)
                & pl.col("subject_type").is_not_null()
                & pl.col("object_type").is_not_null()
                & pl.col("edge_type").is_not_null()
            )
            .select(pl.len())
            .collect()
            .item()
        )
        total_rows += n
        total_mal += mal
        triple_filled += tf
        triple_filled_among_mal += tfm
        if mal > 0:
            sc = (
                pl.scan_parquet(f)
                .filter(pl.col("label") == 1)
                .group_by("scenario")
                .agg(pl.len().alias("n"))
                .collect()
            )
            for sid, cnt in sc.iter_rows():
                if sid is not None:
                    per_scenario[sid] = per_scenario.get(sid, 0) + int(cnt)

    print(f"Featured Parquet (botsv2_features_v2/):")
    print(f"  total rows       : {total_rows:,}")
    print(f"  total malicious  : {total_mal:,}   anchor {ANCHORS['total_malicious']:,}   "
          f"delta {total_mal - ANCHORS['total_malicious']:+,}")
    print()
    print("  per-scenario:")
    for sid, cnt in sorted(per_scenario.items()):
        a = ANCHORS.get(sid, 0)
        print(f"    {sid:30s} {cnt:>10,}   anchor {a:>10,}   delta {cnt-a:+,}")

    print()
    print(f"  graph triple filled (overall): {triple_filled:,} ({100*triple_filled/total_rows:.2f}%)")
    print(f"  graph triple filled (malicious only): {triple_filled_among_mal:,} "
          f"({100*triple_filled_among_mal/max(total_mal,1):.2f}% of malicious)")


if __name__ == "__main__":
    main()
