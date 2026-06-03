"""Shared FLASH-on-OpTC building blocks (faithful port of OpTC.ipynb cells
7-10,14-15,21,25). eCAR schema (per ecar.md): each line is one JSON event with
keys action, actorID, objectID, object, pid, ppid, timestamp, properties.

Mirrors server/ml-engine/theia/theia_flash_common.py but for the OpTC/eCAR
data model. Snake_case so it is importable by the entry scripts.
"""
from __future__ import annotations

import json
import math
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv

VECTOR_SIZE = 20                          # OpTC w2v is 20-dim (notebook cell 13)
DUMMIES = {"PROCESS": 0, "FLOW": 1, "FILE": 2, "MODULE": 3}
VALID_OBJECTS = set(DUMMIES)
INVALID_ACTIONS = {"START", "TERMINATE"}

# per-object phrase templates (cell 8)
_FORMATS = {
    "PROCESS": "{parent_image_path} {action} {image_path} {command_line}",
    "FILE": "{image_path} {action} {file_path}",
    "FLOW": "{image_path} {action} {src_ip} {src_port} {dest_ip} {dest_port} {direction}",
    "MODULE": "{image_path} {action} {module_path}",
}
# (actorname, objectname) property keys per object type (cell 9)
_NAME_KEYS = {
    "PROCESS": ("parent_image_path", "image_path"),
    "FILE": ("image_path", "file_path"),
    "MODULE": ("image_path", "module_path"),
    "FLOW": ("image_path", "dest_ip", "dest_port"),
}


def extract_semantic_info(ev: dict):
    """Attach actorname/objectname; drop events missing required props (cell 9)."""
    keys = _NAME_KEYS.get(ev["object"])
    if not keys:
        return None
    props = ev.get("properties", {})
    vals = [props.get(k) for k in keys]
    if all(vals):
        ev["actorname"], ev["objectname"] = vals[0], " ".join(vals[1:])
        return ev
    return None


def sentence_construction(ev: dict):
    fmt = _FORMATS.get(ev["object"], "{image_path} {action} {module_path}")
    try:
        return fmt.format(action=ev["action"], **ev.get("properties", {})).split(" ")
    except KeyError:
        return []


def traversal_rules(events):
    """Keep valid object/action, dedup by (action,actor,object,object,pid,ppid) (cell 7)."""
    out = {}
    for e in events:
        if (e["object"] in VALID_OBJECTS and e["action"] not in INVALID_ACTIONS
                and e["actorID"] != e["objectID"]):
            out[(e["action"], e["actorID"], e["objectID"], e["object"],
                 e["pid"], e["ppid"])] = e
    return list(out.values())


def transform(events):
    """Raw eCAR dicts -> sorted DataFrame with a 'phrase' token list (cell 9)."""
    labeled = [e for e in (extract_semantic_info(x) for x in events) if e]
    data = traversal_rules(labeled)
    keep = []
    for e in data:
        ph = sentence_construction(e)
        if ph:
            e["phrase"] = ph
            keep.append(e)
    df = pd.DataFrame(keep)
    df["timestamp"] = pd.to_datetime(df["timestamp"].astype(str).str[:-6],
                                     errors="coerce")
    df.sort_values("timestamp", inplace=True)
    return df


def featurize(df, w2v, enc):
    """DataFrame -> (features, labels, edge_index, mapp, lblmap, neimap) (cell 10)."""
    nodes, labels, lblmap, neimap, edges = {}, {}, {}, {}, []
    for _, row in df.iterrows():
        a, o, ot = row["actorID"], row["objectID"], row["object"]
        nodes.setdefault(a, []).extend(row["phrase"])
        nodes.setdefault(o, []).extend(row["phrase"])
        labels[a] = DUMMIES.get("PROCESS", -1)
        labels[o] = DUMMIES.get(ot, -1)
        lblmap[a] = row["actorname"]; lblmap[o] = row["objectname"]
        neimap.setdefault(a, set()).add(row["objectname"])
        neimap.setdefault(o, set()).add(row["actorname"])
        edges.append((a, o))
    feats, flabels, eidx, node_index = [], [], [[], []], {}
    for nid, phrases in nodes.items():
        if not (len(phrases) == 1 and phrases[0] == "DELETE"):
            feats.append(infer(phrases, w2v, enc))
            flabels.append(labels[nid])
            node_index[nid] = len(feats) - 1
    for s, t in edges:
        if s in node_index and t in node_index:
            eidx[0].append(node_index[s]); eidx[1].append(node_index[t])
    return feats, np.array(flabels), eidx, list(node_index.keys()), lblmap, neimap


class GCN(torch.nn.Module):
    """SAGEConv 20->32->20 + linear head to 4 classes (cell 15)."""
    def __init__(self):
        super().__init__()
        self.conv1 = SAGEConv(VECTOR_SIZE, 32, normalize=True)
        self.conv2 = SAGEConv(32, VECTOR_SIZE, normalize=True)
        self.linear = nn.Linear(VECTOR_SIZE, len(DUMMIES))

    def forward(self, x, edge_index):
        return F.softmax(self.linear(self.encode(x, edge_index)), dim=1)

    def encode(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
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
    """Mean positional Word2Vec embedding of a node's token document (cell 14)."""
    we = [w2v.wv[w] for w in doc if w in w2v.wv]
    if not we:
        return np.zeros(VECTOR_SIZE)
    e = torch.tensor(np.array(we), dtype=torch.float)
    if len(doc) < 100000:
        e = enc.embed(e)
    return e.detach().cpu().numpy().mean(axis=0)


def load_events(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [json.loads(line) for line in f if line.strip()]
