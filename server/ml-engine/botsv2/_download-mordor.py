"""Download every Mordor zip/tar.gz from UraSecTeam/mordor into
J:/THESIS-EDR/datasets/mordor/raw/, preserving subdirectory structure.
Parallel downloads via threadpool. Skips files that already exist with
matching size from the GitHub API tree listing.
"""
from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import urllib.request
import urllib.error
import json

API = "https://api.github.com/repos/UraSecTeam/mordor/git/trees/master?recursive=1"
RAW = "https://raw.githubusercontent.com/UraSecTeam/mordor/master/"
OUT = Path("J:/THESIS-EDR/datasets/mordor/raw")


def list_archives() -> list[dict]:
    with urllib.request.urlopen(API, timeout=30) as r:
        tree = json.load(r)["tree"]
    return [
        t for t in tree
        if t["path"].startswith("datasets/") and t["type"] == "blob"
        and (t["path"].endswith(".zip") or t["path"].endswith(".tar.gz"))
    ]


def download_one(rec: dict) -> tuple[str, str]:
    path = rec["path"]
    size = rec.get("size", 0)
    dest = OUT / path
    if dest.exists() and dest.stat().st_size == size:
        return path, "skip"
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = RAW + path
    try:
        with urllib.request.urlopen(url, timeout=60) as r, open(dest, "wb") as f:
            f.write(r.read())
        return path, "ok"
    except Exception as e:
        return path, f"FAIL {e}"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    archives = list_archives()
    print(f"Found {len(archives)} archives, total "
          f"{sum(a.get('size',0) for a in archives)/1e6:.1f} MB", flush=True)
    started = time.time()
    ok = skip = fail = 0
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(download_one, a): a for a in archives}
        for i, fut in enumerate(as_completed(futures), 1):
            path, status = fut.result()
            if status == "ok":
                ok += 1
            elif status == "skip":
                skip += 1
            else:
                fail += 1
                print(f"  [{i}/{len(archives)}] {status} {path}", flush=True)
            if i % 20 == 0:
                print(f"  ... {i}/{len(archives)}  ok={ok} skip={skip} fail={fail}", flush=True)
    elapsed = time.time() - started
    print(f"\nDone in {elapsed:.1f}s — ok={ok} skip={skip} fail={fail}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
