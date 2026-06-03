"""Train OUR OWN Word2Vec on OpTC token documents (the shared feature foundation
for both our self-supervised and supervised GraphSAGE models).

Uses the per-host caches from prepare_cache.py. Trains on ALL hosts' per-node
token docs (unsupervised — no malicious labels involved; matches FLASH applying
one w2v across eval hosts). Hyperparams mirror OpTC.ipynb cell 13
(vector_size=20, window=5, min_count=1) with configurable epochs.

  W2V_EPOCHS=50 RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/train_word2vec.py
"""
from __future__ import annotations
import os, pickle, time
from pathlib import Path
from gensim.models import Word2Vec
import optc_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
OUT = CODE_ROOT / "trained_weights" / "optc_ours"
OUT.mkdir(parents=True, exist_ok=True)
HOSTS = ["0051", "0201", "0501"]
EPOCHS = int(os.environ.get("W2V_EPOCHS", "50"))


def main():
    t0 = time.time()
    sentences = []
    for host in HOSTS:
        c = pickle.load(open(CODE_ROOT / f"_cache_{host}.pkl", "rb"))
        sentences.extend(c["node_docs"])
        print(f"  + host {host}: {len(c['node_docs']):,} node-docs "
              f"(total {len(sentences):,})", flush=True)
    print(f"training Word2Vec dim={fc.VECTOR_SIZE} epochs={EPOCHS} "
          f"on {len(sentences):,} docs ...", flush=True)
    w2v = Word2Vec(sentences=sentences, vector_size=fc.VECTOR_SIZE, window=5,
                   min_count=1, workers=8, epochs=EPOCHS, seed=42)
    path = OUT / "w2v_optc_ours.model"
    w2v.save(str(path))
    print(f"[done] vocab={len(w2v.wv):,} -> {path} ({time.time()-t0:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
