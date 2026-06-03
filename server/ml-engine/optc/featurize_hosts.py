"""Turn each host's cached token docs into w2v feature matrices, using OUR trained
Word2Vec. Writes _feat_<host>_<tag>.npz (X float32 [N,20], y int8 [N]) so model
training/eval never repeats the (slow) w2v inference.

  W2V_PATH=trained_weights/optc_ours/w2v_optc_ours.model FEAT_TAG=ours \
    RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/featurize_hosts.py
"""
from __future__ import annotations
import os, pickle, time
from pathlib import Path
import numpy as np
from gensim.models import Word2Vec
import optc_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
HOSTS = ["0051", "0201", "0501"]
W2V_PATH = CODE_ROOT / os.environ.get("W2V_PATH", "trained_weights/optc_ours/w2v_optc_ours.model")
TAG = os.environ.get("FEAT_TAG", "ours")


def main():
    enc = fc.PositionalEncoder()
    w2v = Word2Vec.load(str(W2V_PATH))
    print(f"w2v vocab={len(w2v.wv):,} tag={TAG}", flush=True)
    for host in HOSTS:
        out = CODE_ROOT / f"_feat_{host}_{TAG}.npz"
        if out.exists():
            print(f"[skip] {out.name}"); continue
        t0 = time.time()
        c = pickle.load(open(CODE_ROOT / f"_cache_{host}.pkl", "rb"))
        X = np.array([fc.infer(doc, w2v, enc) for doc in c["node_docs"]],
                     dtype=np.float32)
        np.savez(out, X=X, y=c["labels"])
        print(f"[done] {host}: X={X.shape} ({time.time()-t0:.0f}s)", flush=True)
    print("FEATURES READY")


if __name__ == "__main__":
    main()
