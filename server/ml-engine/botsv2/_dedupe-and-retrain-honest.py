"""Build an honest Sysmon-balanced training set:
  A) Dedupe by content hash BEFORE splitting (cuts the 42.75% train-test duplicate leak).
  B) Drop high-cardinality categoricals that act as source-proxies (image,
     command_line, process_name, target_dir, object_basename, image_basename,
     user, parent_command_line, registry_*, http_uri, dns_query, src_ip, dest_ip,
     external_ip, http_user_agent, http_referrer, site).

Kept features (low-cardinality + structural + numeric + .ext):
  edge_type, subject_type, object_type, transport, protocol, app_proto,
  http_method, http_content_type, dns_qtype, dns_rcode, integrity_level,
  suricata_event_type, suricata_alert_category, object_name_ext,
  src_port, dest_port, http_status, http_content_length, bytes, bytes_in,
  bytes_out, packets_in, packets_out, duration, process_id,
  suricata_alert_severity

Output:
  data/sysmon_honest/{train,val,test}.parquet
  models/lgbm_sysmon_honest/  (vanilla LightGBM)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import polars as pl

BASE = Path(__file__).parent
OUT = BASE / "data" / "sysmon_honest"
SEED = 42

# Columns that LEAK source. Dropped at train.
HIGH_CARD_LEAK_COLS = [
    "image", "command_line", "process_name", "image_basename",
    "target_dir", "object_basename", "user", "parent_command_line",
    "registry_key", "registry_value",
    "http_uri", "dns_query", "http_user_agent", "http_referrer", "site",
    "src_ip", "dest_ip", "external_ip",
]


def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def load_sysmon() -> pl.DataFrame:
    files = [
        Path("J:/THESIS-EDR/datasets/botsv2_features/sourcetype=XmlWinEventLog_Microsoft-Windows-Sysmon_Operational/featured.parquet"),
        Path("J:/THESIS-EDR/datasets/botsv2_features/sourcetype=mordor_sysmon/featured.parquet"),
    ]
    return pl.concat([pl.read_parquet(f) for f in files if f.exists()],
                     how="vertical_relaxed")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    log("Loading Sysmon featured data ...")
    df = load_sysmon()
    log(f"  raw rows = {df.height:,}  positives = {int((df['label']==1).sum()):,}")

    # ── A) Content-hash dedupe ──────────────────────────────────────
    # Hash on the model-visible content so two events that look identical
    # to the model can't end up in both train and test.
    log("Computing content hash for dedupe ...")
    hash_cols = ["edge_type", "subject_type", "object_type",
                 "image", "command_line", "object_name", "event_id",
                 "user", "host"]
    hash_cols = [c for c in hash_cols if c in df.columns]
    df = df.with_columns(
        pl.concat_str([pl.col(c).cast(pl.String).fill_null("") for c in hash_cols],
                      separator="|").hash().alias("_h")
    )
    n_before = df.height
    # Keep first row per (hash, label) — preserves both classes if a row
    # happens to appear in both (shouldn't, but defensive).
    df = df.unique(subset=["_h", "label"], keep="first", maintain_order=False)
    log(f"  deduped: {n_before:,} -> {df.height:,} "
        f"({100*(n_before-df.height)/n_before:.1f}% removed)")
    log(f"  positives after dedupe = {int((df['label']==1).sum()):,}")

    # ── Stratified split 60/20/20 ───────────────────────────────────
    pos = df.filter(pl.col("label") == 1).sample(fraction=1.0, shuffle=True, seed=SEED)
    neg = df.filter(pl.col("label") == 0).sample(fraction=1.0, shuffle=True, seed=SEED)

    def split(part):
        n = part.height
        a = int(n * 0.6); b = a + int(n * 0.2)
        return part[:a], part[a:b], part[b:]

    p_tr, p_v, p_t = split(pos)
    n_tr, n_v, n_t = split(neg)

    splits = {
        "train": pl.concat([p_tr, n_tr]).sample(fraction=1.0, shuffle=True, seed=SEED),
        "val":   pl.concat([p_v,  n_v]).sample(fraction=1.0, shuffle=True, seed=SEED),
        "test":  pl.concat([p_t,  n_t]).sample(fraction=1.0, shuffle=True, seed=SEED),
    }
    for name, sp in splits.items():
        sp = sp.drop("_h")
        path = OUT / f"{name}.parquet"
        sp.write_parquet(path, compression="zstd", compression_level=3)
        pos_n = int((sp["label"] == 1).sum())
        log(f"  {name}: {sp.height:,} rows ({pos_n:,} pos = {100*pos_n/sp.height:.1f}%)")

    # ── Swap into data/stratified so train.py picks it up ───────────
    stratified = BASE / "data" / "stratified"
    backup = BASE / "data" / "stratified_pre_honest"
    if not backup.exists():
        shutil.copytree(stratified, backup)
    for name in ("train", "val", "test"):
        shutil.copy2(OUT / f"{name}.parquet", stratified / f"{name}.parquet")

    # ── B) Build --drop-feature CLI args for leak-causing columns ──
    drop_args = []
    drop_args += ["--drop-feature", "sourcetype"]
    drop_args += ["--drop-feature", "event_id"]
    for col in HIGH_CARD_LEAK_COLS:
        drop_args += ["--drop-feature", col]

    log("=== Train vanilla LightGBM (honest features only) ===")
    rc = subprocess.call(
        [sys.executable, "train.py", "--split", "stratified",
         "--tag", "sysmon_honest", "--no-xt", *drop_args],
        cwd=BASE,
    )

    # Restore original stratified data
    for name in ("train", "val", "test"):
        shutil.copy2(backup / f"{name}.parquet", stratified / f"{name}.parquet")

    if rc != 0:
        return rc
    log("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
