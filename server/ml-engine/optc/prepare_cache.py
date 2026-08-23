"""Parse each OpTC attack host ONCE into a reusable, w2v-independent cache so the
expensive json.loads + transform + graph-build is not repeated by every model.

Per host writes _cache_<host>.pkl = dict(
    node_docs : list[list[str]]   per-node token document (order == mapp)
    labels    : np.int8[N]        node-type label 0..3 (PROCESS/FLOW/FILE/MODULE)
    edges     : [[src_idx...],[dst_idx...]]
    mapp      : list[str]         node index -> uuid
    gt        : list[str]         GT malicious uuids present on this host
)

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/prepare_cache.py
"""
from __future__ import annotations
import os, pickle, time
from pathlib import Path
import numpy as np
import optc_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("OPTC_DATA", CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "_optc_gt"))
GT_TXT = CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "data_files" / "optc.txt"
HOSTS = ["0051", "0201", "0501"]


def build_graph_docs(df):
    """Like fc.featurize but returns RAW token docs (no w2v) + labels/edges/mapp."""
    nodes, labels, edges = {}, {}, []
    for _, row in df.iterrows():
        a, o, ot = row["actorID"], row["objectID"], row["object"]
        nodes.setdefault(a, []).extend(row["phrase"])
        nodes.setdefault(o, []).extend(row["phrase"])
        labels[a] = fc.DUMMIES.get("PROCESS", -1)
        labels[o] = fc.DUMMIES.get(ot, -1)
        edges.append((a, o))
    node_docs, flabels, node_index = [], [], {}
    for nid, doc in nodes.items():
        if not (len(doc) == 1 and doc[0] == "DELETE"):
            node_index[nid] = len(node_docs)
            node_docs.append(doc)
            flabels.append(labels[nid])
    eidx = [[], []]
    for s, t in edges:
        if s in node_index and t in node_index:
            eidx[0].append(node_index[s]); eidx[1].append(node_index[t])
    return node_docs, np.array(flabels, dtype=np.int8), eidx, list(node_index.keys())


def main():
    GT_ALL = set(GT_TXT.read_text(encoding="utf-8").split())
    for host in HOSTS:
        out = CODE_ROOT / f"_cache_{host}.pkl"
        if out.exists():
            print(f"[skip] {out.name} exists"); continue
        t0 = time.time()
        events = fc.load_events(DATA / f"SysClient{host}.systemia.com.txt")
        ent = {e["actorID"] for e in events} | {e["objectID"] for e in events}
        gt = [g for g in GT_ALL if g in ent]
        df = fc.transform(events)
        node_docs, labels, edges, mapp = build_graph_docs(df)
        pickle.dump({"node_docs": node_docs, "labels": labels, "edges": edges,
                     "mapp": mapp, "gt": gt}, open(out, "wb"), protocol=4)
        print(f"[done] {host}: events={len(events):,} nodes={len(mapp):,} "
              f"edges={len(edges[0]):,} GT={len(gt)} ({time.time()-t0:.0f}s)", flush=True)
    print("CACHE READY")


if __name__ == "__main__":
    main()
