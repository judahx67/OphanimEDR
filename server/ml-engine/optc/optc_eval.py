"""Shared honest-evaluation helpers for OpTC models (used by reproduce + our
models). Reports RAW (no 2-hop) AND 2-hop-adjusted, the carry-over protocol.

The 2-hop closure here is an adjacency-list BFS (O(N+E) per query) — semantically
identical to FLASH's Get_Adjacent(hops=2) but ~100x faster than its
O(edges x ids) double loop (0501 went from 17min to seconds).
"""
from __future__ import annotations
from collections import defaultdict


def build_adjacency(edges, mapp):
    """uuid -> set(neighbor uuid), undirected, from edge_index over node indices."""
    adj = defaultdict(set)
    for s, t in zip(edges[0], edges[1]):
        us, ut = mapp[s], mapp[t]
        adj[us].add(ut)
        adj[ut].add(us)
    return adj


def two_hop(ids, adj):
    """All uuids within 2 undirected hops of `ids` (matches FLASH Get_Adjacent hops=2:
    a node with no incident edge is excluded; ids with edges are included)."""
    h1 = set()
    for n in ids:
        nb = adj.get(n)
        if nb:
            h1.add(n)
            h1 |= nb
    h2 = set(h1)
    for n in h1:
        nb = adj.get(n)
        if nb:
            h2 |= nb
    return h2


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def score(alert, gt, all_ids, adj):
    """Return dict with RAW + 2-hop metrics for an alert set vs ground truth.

    alert, gt, all_ids: sets of uuids. adj: from build_adjacency.
    2-hop rule (FLASH helper): forgive FPs within 2 hops of GT; promote FNs within
    2 hops of a TP.
    """
    TP, FP, FN = alert & gt, alert - gt, gt - alert
    TN = all_ids - (gt | alert)
    p, r, f = prf(len(TP), len(FP), len(FN))

    two_gp = two_hop(gt, adj)
    two_tp = two_hop(TP, adj)
    FPL = FP - two_gp
    TPL = TP | (FN & two_tp)
    FNa = FN - two_tp
    p2, r2, f2 = prf(len(TPL), len(FPL), len(FNa))
    return {
        "raw": (len(TP), len(FP), len(FN), len(TN), p, r, f),
        "twohop": (len(TPL), len(FPL), len(FNa), p2, r2, f2),
        "forgave_fp": len(FP) - len(FPL),
        "promoted_fn": len(TPL) - len(TP),
    }


def fmt(host, n_nodes, n_gt, n_alert, s, extra=""):
    tp, fp, fn, tn, p, r, f = s["raw"]
    tpl, fpl, fna, p2, r2, f2 = s["twohop"]
    return (f"host {host}: nodes={n_nodes:,} GT={n_gt} alerts={n_alert} {extra}\n"
            f"  RAW   TP={tp} FP={fp} FN={fn}  P={p:.4f} R={r:.4f} F1={f:.4f}\n"
            f"  2HOP  TP={tpl} FP={fpl} FN={fna}  P={p2:.4f} R={r2:.4f} F1={f2:.4f}  "
            f"(forgave {s['forgave_fp']} FP, promoted {s['promoted_fn']} FN->TP)")
