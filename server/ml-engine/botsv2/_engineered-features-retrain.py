"""Re-extract Sysmon features (now with engineered booleans) → re-label by
boolean count → retrain.

Labelling rule:
  - sum(engineered booleans) >= 2  => label = 1
  - sum == 0                       => label = 0
  - sum == 1                       => drop (ambiguous)

Why: gives clean ground truth from feature pattern matches. Both Mordor and
BOTSv2 contribute to BOTH classes, removing the source leak. Model learns
which boolean COMBINATIONS predict attack (not just OR — tree boosting
captures conjunctive patterns and confidence scaling).

Pipeline:
  1) Re-extract `XmlWinEventLog_Microsoft-Windows-Sysmon_Operational` and
     `mordor_sysmon` partitions  -> botsv2_features_v2/
  2) Move the two re-extracted partitions back into botsv2_features/
  3) Build engineered-labelled Sysmon-only train/val/test
  4) Train vanilla LightGBM on engineered booleans + structural + ports/bytes
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

import polars as pl

BASE = Path(__file__).parent
FEATURES_DIR = Path("J:/THESIS-EDR/datasets/botsv2_features")
FEATURES_V2 = Path("J:/THESIS-EDR/datasets/botsv2_features_v2")
OUT = BASE / "data" / "sysmon_engineered"
SEED = 42

SYSMON_PARTITIONS = [
    "XmlWinEventLog_Microsoft-Windows-Sysmon_Operational",
    "mordor_sysmon",
]


def log(m: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def re_extract():
    """Run extract_features.py --only for each Sysmon partition so the new
    engineered-boolean columns are populated. extract_features writes to
    botsv2_features_v2/."""
    if FEATURES_V2.exists():
        shutil.rmtree(FEATURES_V2)
    for st in SYSMON_PARTITIONS:
        log(f"=== extract_features.py --only {st} ===")
        rc = subprocess.call(
            [sys.executable, "extract_features.py", "--only", st],
            cwd=BASE,
        )
        if rc != 0:
            raise SystemExit(f"extract_features failed on {st}")
        src = FEATURES_V2 / f"sourcetype={st}"
        dst = FEATURES_DIR / f"sourcetype={st}"
        if src.exists():
            log(f"  move {src.name} -> {dst}")
            if dst.exists():
                shutil.rmtree(dst)
            shutil.move(str(src), str(dst))


def load_engineered_features() -> tuple[pl.DataFrame, list[str]]:
    sys.path.insert(0, str(BASE.parents[1]))  # for botsv2_parsers
    from botsv2_parsers.engineered_features import FEATURE_NAMES
    parts = []
    for st in SYSMON_PARTITIONS:
        f = FEATURES_DIR / f"sourcetype={st}" / "featured.parquet"
        if not f.exists():
            log(f"MISSING {f}"); continue
        df = pl.read_parquet(f)
        n_eng_pos = int(sum(df[c].sum() for c in FEATURE_NAMES if c in df.columns))
        log(f"  {st}: {df.height:,} rows  total bool-fires={n_eng_pos:,}")
        parts.append(df)
    return pl.concat(parts, how="vertical_relaxed"), FEATURE_NAMES


def relabel_by_count(df: pl.DataFrame, feature_names: list[str]) -> pl.DataFrame:
    """Drop the old `label` column; assign new label from boolean count.
      label = 1 if >=2 booleans, 0 if 0 booleans, drop rows with exactly 1."""
    bool_cols = [c for c in feature_names if c in df.columns]
    df = df.with_columns(
        sum(pl.col(c).fill_null(0).cast(pl.Int32) for c in bool_cols).alias("_bool_count")
    )
    df = df.drop("label")
    df = df.with_columns(
        pl.when(pl.col("_bool_count") >= 2).then(1)
          .when(pl.col("_bool_count") == 0).then(0)
          .otherwise(None).alias("label").cast(pl.Int8)
    )
    n_before = df.height
    df = df.filter(pl.col("label").is_not_null())
    log(f"  relabel: {n_before:,} -> {df.height:,} "
        f"(dropped {n_before-df.height:,} with exactly 1 boolean)")
    n_pos = int((df["label"] == 1).sum())
    log(f"  positives: {n_pos:,} ({100*n_pos/df.height:.2f}%)")
    return df


def split(df: pl.DataFrame) -> dict[str, pl.DataFrame]:
    pos = df.filter(pl.col("label") == 1).sample(fraction=1.0, shuffle=True, seed=SEED)
    neg = df.filter(pl.col("label") == 0).sample(fraction=1.0, shuffle=True, seed=SEED)
    def s(p):
        n = p.height; a = int(n * 0.6); b = a + int(n * 0.2)
        return p[:a], p[a:b], p[b:]
    p_tr, p_v, p_t = s(pos)
    n_tr, n_v, n_t = s(neg)
    return {
        "train": pl.concat([p_tr, n_tr]).sample(fraction=1.0, shuffle=True, seed=SEED),
        "val":   pl.concat([p_v,  n_v]).sample(fraction=1.0, shuffle=True, seed=SEED),
        "test":  pl.concat([p_t,  n_t]).sample(fraction=1.0, shuffle=True, seed=SEED),
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    log("=== STEP 1: re-extract Sysmon partitions with engineered booleans ===")
    re_extract()

    log("=== STEP 2: load + label by boolean count ===")
    df, feat_names = load_engineered_features()
    log(f"loaded {df.height:,} rows from {len(SYSMON_PARTITIONS)} partitions")

    df = relabel_by_count(df, feat_names)

    splits = split(df)
    for name, sp in splits.items():
        path = OUT / f"{name}.parquet"
        sp.write_parquet(path, compression="zstd", compression_level=3)
        n_pos = int((sp["label"] == 1).sum())
        log(f"  wrote {name}: {sp.height:,} rows ({n_pos:,} pos = {100*n_pos/sp.height:.1f}%)")

    log("=== STEP 3: swap into data/stratified for train.py ===")
    stratified = BASE / "data" / "stratified"
    backup = BASE / "data" / "stratified_pre_engineered"
    if not backup.exists():
        shutil.copytree(stratified, backup)
    for name in ("train", "val", "test"):
        shutil.copy2(OUT / f"{name}.parquet", stratified / f"{name}.parquet")

    log("=== STEP 4: train vanilla LightGBM, drop ALL high-card categoricals ===")
    # Drop everything except: edge_type, subject_type, object_type, numeric
    # (including the 38 engineered booleans), object_name_ext.
    DROP = [
        "sourcetype", "event_id",  # source proxies
        "image", "command_line", "process_name", "image_basename",
        "target_dir", "object_basename", "user", "parent_command_line",
        "parent_image", "registry_key", "registry_value",
        "http_uri", "dns_query", "http_user_agent", "http_referrer", "site",
        "src_ip", "dest_ip", "external_ip",
        "http_method", "http_content_type", "dns_qtype", "dns_rcode",
        "transport", "protocol", "app_proto", "integrity_level",
        "suricata_event_type", "suricata_alert_category",
    ]
    drop_args = []
    for col in DROP:
        drop_args += ["--drop-feature", col]
    rc = subprocess.call(
        [sys.executable, "train.py", "--split", "stratified",
         "--tag", "engineered", "--no-xt", *drop_args],
        cwd=BASE,
    )

    for name in ("train", "val", "test"):
        shutil.copy2(backup / f"{name}.parquet", stratified / f"{name}.parquet")

    if rc != 0:
        return rc
    log("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
