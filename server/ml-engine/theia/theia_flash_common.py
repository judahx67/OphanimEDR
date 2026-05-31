"""Shared FLASH/THEIA-E3 building blocks used by both evaluate.py and
train_gnn.py. Snake_case so it is importable (entry scripts are run directly).
Faithful to Theia.ipynb cells 5,7,8,13,17.
"""
from __future__ import annotations

import json
import math
import os
import re

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv

VECTOR_SIZE = 30
DUMMIES = {"SUBJECT_PROCESS": 0, "MemoryObject": 1, "FILE_OBJECT_BLOCK": 2,
           "NetFlowObject": 3, "PRINCIPAL_REMOTE": 4, "PRINCIPAL_LOCAL": 5}

_uuid = re.compile(r'uuid\":\"(.*?)\"')
_type = re.compile(r'type\":\"(.*?)\"')
_src = re.compile(r'subject\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
_dst1 = re.compile(r'predicateObject\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
_dst2 = re.compile(r'predicateObject2\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
_time = re.compile(r'timestampNanos\":(.*?),')

# ---- CDM18 parse (two-pass, memory-bounded) -------------------------------


def collect_referenced_uuids(split: str) -> set:
    """Pass A: UUIDs referenced as src/dst by Events in one split."""
    need = set()
    with open(split, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if ".Event" not in line:
                continue
            for pat in (_src, _dst1, _dst2):
                d = pat.findall(line)
                if d and d[0] != "null":
                    need.add(d[0])
    return need


def build_node_map(base: str, need: set) -> dict:
    """Pass B: resolve type only for needed UUIDs, scanning all splits."""
    m = {}
    for i in range(100):
        p = base if i == 0 else f"{base}.{i}"
        if not os.path.exists(p):
            break
        print(f"  node-map: {p} ({len(m):,}/{len(need):,} resolved)", flush=True)
        with open(p, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if any(t in line for t in (".Event", ".Host", ".TimeMarker",
                        ".StartMarker", ".UnitDependency", ".EndMarker")):
                    continue
                u = _uuid.findall(line)
                if not u or u[0] not in need or u[0] in m:
                    continue
                u = u[0]
                st = _type.findall(line)
                if st:
                    m[u] = st[0]
                elif ".MemoryObject" in line:
                    m[u] = "MemoryObject"
                elif ".NetFlowObject" in line:
                    m[u] = "NetFlowObject"
                elif ".UnnamedPipeObject" in line:
                    m[u] = "UnnamedPipeObject"
        if len(m) >= len(need):
            print("  all needed nodes resolved, stopping early", flush=True)
            break
    return m


def write_edges(split: str, node_map: dict, out: str) -> str:
    if os.path.exists(out):
        print(f"  edges: {out} exists")
        return out
    with open(split, encoding="utf-8", errors="ignore") as f, \
            open(out, "w", encoding="utf-8") as fw:
        for line in f:
            if ".Event" not in line:
                continue
            st, ts, src = _type.findall(line), _time.findall(line), _src.findall(line)
            if not st or not ts or not src or src[0] not in node_map:
                continue
            etype, timestamp, sid = st[0], ts[0], src[0]
            for pat in (_dst1, _dst2):
                d = pat.findall(line)
                if d and d[0] != "null" and d[0] in node_map:
                    fw.write(f"{sid}\t{node_map[sid]}\t{d[0]}\t{node_map[d[0]]}\t{etype}\t{timestamp}\n")
    return out


def parse_split(base: str, split: str, out_txt: str) -> str:
    """Full two-pass parse of one split into a tab-separated edge file."""
    if os.path.exists(out_txt):
        print(f"parse: {out_txt} exists, skipping")
        return out_txt
    print("pass A: collecting referenced UUIDs...", flush=True)
    need = collect_referenced_uuids(split)
    print(f"  {len(need):,} referenced uuids", flush=True)
    print("pass B: resolving node types over all splits...", flush=True)
    nmap = build_node_map(base, need)
    print(f"  {len(nmap):,} nodes resolved", flush=True)
    tmp = write_edges(split, nmap, split + ".edges.tmp")
    os.replace(tmp, out_txt)
    print(f"wrote {out_txt}", flush=True)
    return out_txt


def _dig(d, keys):
    for k in keys:
        d = d.get(k) if isinstance(d, dict) else None
        if d is None:
            return ""
    return d if isinstance(d, str) else ""


def add_attributes(d: pd.DataFrame, p: str) -> pd.DataFrame:
    """Re-read raw JSON split to merge cmdLine/path onto edges (cell 13)."""
    rows = []
    with open(p, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "EVENT" not in line:
                continue
            x = json.loads(line)
            ev = x["datum"].get("com.bbn.tc.schema.avro.cdm18.Event")
            if not ev:
                continue
            g = lambda *ks: _dig(ev, ks)
            action = ev.get("type", "")
            actor = g("subject", "com.bbn.tc.schema.avro.cdm18.UUID")
            obj = g("predicateObject", "com.bbn.tc.schema.avro.cdm18.UUID")
            ts = ev.get("timestampNanos", "")
            cmd = g("properties", "map", "cmdLine")
            path = g("predicateObjectPath", "string")
            path2 = g("predicateObject2Path", "string")
            obj2 = g("predicateObject2", "com.bbn.tc.schema.avro.cdm18.UUID")
            if obj2:
                rows.append({"actorID": actor, "objectID": obj2, "action": action,
                             "timestamp": ts, "exec": cmd, "path": path2})
            rows.append({"actorID": actor, "objectID": obj, "action": action,
                         "timestamp": ts, "exec": cmd, "path": path})
    rdf = pd.DataFrame.from_records(rows).astype(str)
    d = d.astype(str)
    return d.merge(rdf, how="inner",
                   on=["actorID", "objectID", "action", "timestamp"]).drop_duplicates()


# ---- graph + model --------------------------------------------------------


def prepare_graph(df: pd.DataFrame):
    nodes, labels, edges = {}, {}, []
    for _, row in df.iterrows():
        props = [row["exec"], row["action"]] + ([row["path"]] if row["path"] else [])
        a, o = row["actorID"], row["objectID"]
        nodes.setdefault(a, []).extend(props)
        labels[a] = DUMMIES.get(row["actor_type"], 0)
        nodes.setdefault(o, []).extend(props)
        labels[o] = DUMMIES.get(row["object"], 0)
        edges.append((a, o))
    feats, flabels, eidx, idx = [], [], [[], []], {}
    for nid, props in nodes.items():
        idx[nid] = len(feats)
        feats.append(props)
        flabels.append(labels[nid])
    for s, t in edges:
        eidx[0].append(idx[s])
        eidx[1].append(idx[t])
    return feats, flabels, eidx, list(idx.keys())


class GCN(torch.nn.Module):
    def __init__(self, in_c, out_c):
        super().__init__()
        self.conv1 = SAGEConv(in_c, 32, normalize=True)
        self.conv2 = SAGEConv(32, out_c, normalize=True)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index).relu()
        x = F.dropout(x, p=0.5, training=self.training)
        return self.conv2(x, edge_index)


class PositionalEncoder:
    def __init__(self, d_model=VECTOR_SIZE, max_len=100000):
        pos = torch.arange(max_len).unsqueeze(1)
        div = torch.exp(torch.arange(0, d_model, 2) * (-math.log(10000.0) / d_model))
        self.pe = torch.zeros(max_len, d_model)
        self.pe[:, 0::2] = torch.sin(pos * div)
        self.pe[:, 1::2] = torch.cos(pos * div)

    def embed(self, x):
        return x + self.pe[: x.size(0)]


def infer(doc, w2v, enc):
    """Mean Word2Vec embedding of a node's token document (cell 17)."""
    we = [w2v.wv[w] for w in doc if w in w2v.wv]
    if not we:
        return np.zeros(VECTOR_SIZE)  # notebook bug was zeros(20)
    e = torch.tensor(np.array(we), dtype=torch.float)
    if len(doc) < 100000:
        e = enc.embed(e)
    return e.detach().cpu().numpy().mean(axis=0)
