"""One-time: build a replay-ready enriched edge file for the THEIA test split.

evaluate.py scores `theia_test.txt` (actorID,actor_type,objectID,object_type,
action,timestamp) AFTER merging cmdLine/path via fc.add_attributes (the v3
weights were trained WITH those attributes — train_gnn.py:58). The live replayer
needs the same enriched edges so full-graph scoring is faithful, plus the GT
label so the dashboard can show flagged∩GT.

Output (tab-separated, one edge per line):
  actorID  actor_type  objectID  object_type  action  timestamp  exec  path  label

Run with the research venv (has pandas):
  J:/THESIS-EDR/RESEARCH/.venv/Scripts/python.exe _build_enriched_edges.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

import theia_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = CODE_ROOT.parents[2] / "external" / "Flash-IDS"
TEST_SPLIT = str(DATA_ROOT / "ta1-theia-e3-official-6r.json.8")
TEST_TXT = DATA_ROOT / "theia_test.txt"
OUT = DATA_ROOT / "theia_test_enriched.txt"
GT_FILE = DATA_ROOT / "data_files" / "theia.json"


def _clean(s: str) -> str:
    """Strip tabs/newlines so columns stay parseable."""
    return str(s).replace("\t", " ").replace("\n", " ").replace("\r", " ")


def main():
    print(f"reading {TEST_TXT} ...", flush=True)
    rows = [l.split("\t") for l in TEST_TXT.read_text(
        encoding="utf-8", errors="ignore").split("\n")]
    df = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID",
                                     "object", "action", "timestamp"]).dropna()
    df.sort_values("timestamp", inplace=True)
    print(f"  {len(df):,} edges", flush=True)

    print(f"merging cmdLine/path from {TEST_SPLIT} (slow, re-reads raw json) ...",
          flush=True)
    df = fc.add_attributes(df, TEST_SPLIT)
    print(f"  {len(df):,} edges after attribute merge", flush=True)

    gt = {u for u in json.load(open(GT_FILE, encoding="utf-8")) if u}
    print(f"GT malicious uuids: {len(gt):,}", flush=True)

    n_mal = 0
    with open(OUT, "w", encoding="utf-8") as fw:
        for _, r in df.iterrows():
            label = 1 if (r["actorID"] in gt or r["objectID"] in gt) else 0
            n_mal += label
            fw.write("\t".join([
                r["actorID"], r["actor_type"], r["objectID"], r["object"],
                r["action"], r["timestamp"], _clean(r["exec"]),
                _clean(r["path"]), str(label),
            ]) + "\n")
    print(f"wrote {OUT}  ({len(df):,} edges, {n_mal:,} GT-labelled)", flush=True)


if __name__ == "__main__":
    main()
