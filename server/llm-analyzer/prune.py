"""
Subgraph pruner.

Raw 1-hop subgraphs can explode on fan-out patterns (e.g. one socket talking
to 100+ DNS targets) and overflow the LLM's useful context. We compress the
graph before serialisation while preserving what the LLM actually needs:

  1. The flagged edge + its two endpoints (always kept; this is the alert).
  2. Edges touching either alert endpoint (high signal — likely causal context).
  3. Other edges (lower signal — kept only if budget allows).

Within each tier, we collapse repeated patterns: edges sharing
(src_label, edge_type, dst_label) are folded into one "× N similar" line.
This keeps token cost bounded without losing the topology gist.

Returns a structure ready for textual rendering plus per-tier kept/dropped
counters so the prompt can tell the LLM what was elided.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Per-tier edge budget. Tier 0 = unbounded (alert edge), tier 1/2 capped.
MAX_EDGES_TIER1 = 40
MAX_EDGES_TIER2 = 20
# Repeated-edge collapsing threshold: groups with > this many similar edges
# get folded into "× N" summaries.
COLLAPSE_THRESHOLD = 3


@dataclass
class PrunedSubgraph:
    nodes: list[dict]
    edges: list[dict]                # individual kept edges
    collapsed: list[dict]            # {signature, count, sample_dst_names}
    dropped: dict[str, int] = field(default_factory=dict)


def _edge_signature(edge: dict, node_by_id: dict) -> tuple[str, str, str]:
    src = node_by_id.get(edge["src"], {})
    dst = node_by_id.get(edge["dst"], {})
    return (src.get("label", "?"), edge["type"], dst.get("label", "?"))


def _tier(edge: dict, alert_node_ids: set[str]) -> int:
    if edge.get("event_id") and edge["event_id"] == alert_node_ids.get("alert_event_id"):
        return 0
    if edge["src"] in alert_node_ids["endpoints"] or edge["dst"] in alert_node_ids["endpoints"]:
        return 1
    return 2


def prune(subgraph: dict, alert: dict) -> PrunedSubgraph:
    nodes = subgraph.get("nodes", [])
    edges = subgraph.get("edges", [])
    node_by_id = {n["id"]: n for n in nodes}

    alert_event_id = alert.get("event_id", "")
    subj_id = (alert.get("subject") or {}).get("id", "")
    obj_id = (alert.get("object") or {}).get("id", "")
    alert_ctx = {"alert_event_id": alert_event_id, "endpoints": {subj_id, obj_id}}

    # Bucket edges by tier
    tiers: dict[int, list[dict]] = {0: [], 1: [], 2: []}
    for e in edges:
        tiers[_tier(e, alert_ctx)].append(e)

    kept_edges: list[dict] = []
    collapsed: list[dict] = []
    dropped: dict[str, int] = {"tier1_capped": 0, "tier2_capped": 0}

    # Tier 0: always keep (the alert)
    kept_edges.extend(tiers[0])

    # Tier 1 + 2: collapse repeats, then cap
    for tier_id, cap in [(1, MAX_EDGES_TIER1), (2, MAX_EDGES_TIER2)]:
        groups: dict[tuple, list[dict]] = {}
        for e in tiers[tier_id]:
            groups.setdefault(_edge_signature(e, node_by_id), []).append(e)

        tier_kept: list[dict] = []
        for sig, group in groups.items():
            if len(group) > COLLAPSE_THRESHOLD:
                sample_dst_names = [
                    node_by_id.get(g["dst"], {}).get("name", "")
                    for g in group[:3]
                ]
                collapsed.append({
                    "signature": sig,
                    "count": len(group),
                    "sample_dst_names": [n for n in sample_dst_names if n],
                    "any_alert": any(g.get("is_alert") for g in group),
                })
                # Keep one representative so the node stays referenced
                tier_kept.append(group[0])
            else:
                tier_kept.extend(group)

        # Prioritise alert-tagged edges within the tier when capping
        tier_kept.sort(key=lambda e: (not e.get("is_alert"), -(e.get("score") or 0)))
        if len(tier_kept) > cap:
            dropped[f"tier{tier_id}_capped"] = len(tier_kept) - cap
            tier_kept = tier_kept[:cap]
        kept_edges.extend(tier_kept)

    # Keep only nodes referenced by kept edges (plus alert endpoints)
    referenced: set[str] = {subj_id, obj_id}
    for e in kept_edges:
        referenced.add(e["src"])
        referenced.add(e["dst"])
    kept_nodes = [n for n in nodes if n["id"] in referenced]

    dropped["nodes_unreferenced"] = len(nodes) - len(kept_nodes)
    return PrunedSubgraph(
        nodes=kept_nodes, edges=kept_edges,
        collapsed=collapsed, dropped=dropped,
    )
