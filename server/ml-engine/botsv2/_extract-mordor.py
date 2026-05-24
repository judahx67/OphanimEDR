"""Unpack every .zip / .tar.gz under mordor/raw/ to mordor/extracted/.
Preserves the per-scenario directory structure so we can label each event
with its source technique."""
from __future__ import annotations

import sys
import tarfile
import time
import zipfile
from pathlib import Path

RAW = Path("J:/THESIS-EDR/datasets/mordor/raw/datasets")
OUT = Path("J:/THESIS-EDR/datasets/mordor/extracted")


def main() -> int:
    archives = sorted(
        list(RAW.rglob("*.zip")) + list(RAW.rglob("*.tar.gz"))
    )
    print(f"Extracting {len(archives)} archives -> {OUT}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    started = time.time()
    extracted = 0
    skipped = 0
    failed = 0
    for arc in archives:
        # Strip the leading "datasets/" from rel path; keep subdir/scenario layout
        rel = arc.relative_to(RAW)
        dest = OUT / rel.with_suffix("")  # strip .zip or .gz
        if dest.suffix == ".tar":
            dest = dest.with_suffix("")
        if dest.exists() and any(dest.iterdir()):
            skipped += 1
            continue
        dest.mkdir(parents=True, exist_ok=True)
        try:
            if arc.suffix == ".zip":
                with zipfile.ZipFile(arc) as z:
                    z.extractall(dest)
            elif arc.name.endswith(".tar.gz"):
                with tarfile.open(arc, "r:gz") as t:
                    t.extractall(dest)
            extracted += 1
            if extracted % 20 == 0:
                print(f"  ... {extracted} extracted", flush=True)
        except Exception as e:
            failed += 1
            print(f"  FAIL {arc.name}: {e}", flush=True)
    elapsed = time.time() - started
    print(f"\nDone in {elapsed:.1f}s — extracted={extracted} skipped={skipped} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
