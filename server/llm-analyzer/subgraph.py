"""
Pull a k-hop subgraph around a flagged edge from Neo4j and serialize it to
a compact textual form suitable for LLM context.
"""
from __future__ import annotations

from neo4j import Driver

from prune import prune


_KHOP_CYPHER = """
MATCH (start)
WHERE start.uuid IN [$subj_id, $obj_id]
CALL {
    WITH start
    MATCH path = (start)-[*1..{hops}]-(neighbor)
    RETURN nodes(path) AS path_nodes, relationships(path) AS path_rels
}
WITH collect(DISTINCT path_nodes) AS all_node_lists,
     collect(DISTINCT path_rels) AS all_rel_lists
WITH
  [n IN apoc.coll.flatten(all_node_lists) | n] AS raw_nodes,
  [r IN apoc.coll.flatten(all_rel_lists) | r] AS raw_rels
RETURN raw_nodes, raw_rels
"""

# APOC-free version. Neo4j 5 rejects expressions like `[s, o] + collect(...)`
# in the RETURN because `s` and `o` become implicit grouping keys alongside
# the aggregations. Use a variable-length path match and let the cardinality
# explode into rows the driver dedupes via element_id (see pull_subgraph).
_KHOP_CYPHER_NO_APOC = """
MATCH (root)
WHERE root.uuid IN [$subj_id, $obj_id]
OPTIONAL MATCH path = (root)-[*1..1]-(neighbour)
WITH root, path
LIMIT 200
WITH
  collect(DISTINCT root) AS roots,
  collect(path)          AS paths
WITH
  roots,
  [p IN paths WHERE p IS NOT NULL | nodes(p)]         AS node_lists,
  [p IN paths WHERE p IS NOT NULL | relationships(p)] AS rel_lists
RETURN
  roots + reduce(acc=[], xs IN node_lists | acc + xs) AS nodes,
  reduce(acc=[], xs IN rel_lists  | acc + xs)         AS rels
LIMIT 1
"""


def pull_subgraph(driver: Driver, subj_id: str, obj_id: str, hops: int = 2) -> dict:
    """
    Return a compact subgraph dict:
      {"nodes": [{id, label, name, ...}], "edges": [{src, dst, type, event_id, score}]}
    """
    with driver.session() as session:
        result = session.run(
            _KHOP_CYPHER_NO_APOC,
            subj_id=subj_id,
            obj_id=obj_id,
        )
        record = result.single()

    if record is None:
        return {"nodes": [], "edges": []}

    seen_node_ids: set = set()
    nodes: list[dict] = []
    for node in (record["nodes"] or []):
        if node is None:
            continue
        nid = node.element_id
        if nid in seen_node_ids:
            continue
        seen_node_ids.add(nid)
        nodes.append({
            "id": node.get("uuid", nid),
            "label": list(node.labels)[0] if node.labels else "Unknown",
            "name": node.get("name", ""),
            "endpoint_id": node.get("endpoint_id", ""),
        })

    seen_rel_ids: set = set()
    edges: list[dict] = []
    for rel in (record["rels"] or []):
        if rel is None:
            continue
        rid = rel.element_id
        if rid in seen_rel_ids:
            continue
        seen_rel_ids.add(rid)
        edges.append({
            "src": rel.start_node.get("uuid", rel.start_node.element_id),
            "dst": rel.end_node.get("uuid", rel.end_node.element_id),
            "type": rel.type,
            "event_id": rel.get("event_id", ""),
            "score": rel.get("botsv2_ml_score"),
            "is_alert": rel.get("botsv2_ml_alert", False),
            "timestamp": rel.get("timestamp", 0),
        })

    return {"nodes": nodes, "edges": edges}


def subgraph_to_matched(subgraph: dict, max_edges: int = 15) -> tuple[list[dict], list[dict]]:
    """Map the compact subgraph onto the dashboard's matched_nodes/matched_edges
    contract (Incidents.tsx CausalChain). Feeds the causal-chain viz for GNN->LLM
    incidents the same way the rule-engine populates it — the assembly is already
    pulled for the prompt, this just persists it instead of discarding it."""
    name_by_id = {n["id"]: (n.get("name") or n["id"]) for n in subgraph.get("nodes", [])}
    matched_nodes = [
        {
            "id": n["id"],
            "type": (n.get("label") or "Unknown").upper(),
            "name": n.get("name") or n["id"],
        }
        for n in subgraph.get("nodes", [])
    ]
    matched_edges = [
        {
            "event_id": e.get("event_id", ""),
            "edge_type": e.get("type", ""),
            "subject_id": e.get("src", ""),
            "subject_name": name_by_id.get(e.get("src", ""), e.get("src", "")),
            "object_id": e.get("dst", ""),
            "object_name": name_by_id.get(e.get("dst", ""), e.get("dst", "")),
            "timestamp": e.get("timestamp", 0),
        }
        for e in subgraph.get("edges", [])[:max_edges]
    ]
    return matched_nodes, matched_edges


def subgraph_to_text(subgraph: dict, alert: dict) -> str:
    """Render a subgraph as compact text for the LLM prompt.

    Runs the pruner first to bound size. The prompt explicitly tells the LLM
    when nodes/edges were elided so it doesn't over-extrapolate from the
    visible slice.
    """
    pruned = prune(subgraph, alert)
    lines = []

    lines.append("## Flagged Edge")
    lines.append(f"  event_id  : {alert.get('event_id', '?')}")
    lines.append(f"  edge_type : {alert.get('edge_type', '?')}")
    lines.append(f"  subject   : {alert.get('subject', {}).get('name', '?')} "
                 f"[{alert.get('subject', {}).get('node_type', '?')}]")
    lines.append(f"  object    : {alert.get('object', {}).get('name', '?')} "
                 f"[{alert.get('object', {}).get('node_type', '?')}]")
    lines.append(f"  ml_score  : {alert.get('score', 0.0):.4f} (honest, sourcetype-blind)")
    lines.append(f"  sourcetype: {alert.get('sourcetype', 'N/A')}")
    lines.append(f"  endpoint  : {alert.get('endpoint_id', '?')}")
    dedup = alert.get("_dedup_count", 0)
    if dedup:
        lines.append(f"  NOTE      : {dedup} additional identical alerts suppressed (same src/dst/edge in last 5 min)")
    lines.append("")

    lines.append(f"## Subgraph Nodes ({len(pruned.nodes)} kept)")
    for n in pruned.nodes:
        lines.append(f"  [{n['label']}] {n['name']!r}  id={n['id']}")

    lines.append("")
    lines.append(f"## Subgraph Edges ({len(pruned.edges)} kept)")
    for e in pruned.edges:
        alert_tag = " *** ALERT ***" if e.get("is_alert") else ""
        score_str = ""
        if e.get("score") is not None:
            score_str = f"  score={e['score']:.3f}"
        lines.append(f"  {e['src'][:12]}..  --[{e['type']}]-->  {e['dst'][:12]}..{score_str}{alert_tag}")

    if pruned.collapsed:
        lines.append("")
        lines.append("## Repeated Patterns (collapsed)")
        for c in pruned.collapsed:
            src_lbl, etype, dst_lbl = c["signature"]
            samples = ", ".join(repr(s) for s in c["sample_dst_names"][:3])
            alert_tag = "  *** contains ALERT ***" if c["any_alert"] else ""
            lines.append(
                f"  [{src_lbl}] --[{etype}]--> [{dst_lbl}]  × {c['count']} similar  "
                f"e.g. {samples}{alert_tag}"
            )

    elided_bits = [f"{k}={v}" for k, v in pruned.dropped.items() if v]
    if elided_bits:
        lines.append("")
        lines.append(f"## Elided\n  {', '.join(elided_bits)}")
        lines.append("  (LLM note: above counts were dropped to fit context; "
                     "absence does not imply benignity)")

    return "\n".join(lines)


def node_subgraph_to_text(subgraph: dict, alert: dict) -> str:
    """Render a THEIA GNN node-seed alert + its 1-hop neighbourhood for the LLM.

    Unlike the BOTSv2 edge path, the FLASH GNN flags a *node* (the seed that
    survived all explain-away rounds), not a single causal edge. The flagged
    node and its provenance context are what the analyst needs to reason about.
    """
    pruned = prune(subgraph, alert)
    subj = alert.get("subject") or {}
    lines = []

    lines.append("## Flagged Node (FLASH GNN anomaly seed)")
    lines.append(f"  node_id   : {alert.get('event_id', '?')}")
    lines.append(f"  node_type : {subj.get('node_type', '?')}")
    lines.append(f"  name      : {subj.get('name', '') or '(unnamed)'}")
    lines.append(f"  detector  : {alert.get('edge_type', 'gnn')} "
                 f"(20-shard explain-away survivor; batch-relative anomaly)")
    lines.append(f"  endpoint  : {alert.get('endpoint_id', '?')}")
    dedup = alert.get("_dedup_count", 0)
    if dedup:
        lines.append(f"  NOTE      : {dedup} additional identical seed alerts suppressed (last 5 min)")
    lines.append("")

    lines.append(f"## 1-hop Neighbourhood Nodes ({len(pruned.nodes)} kept)")
    for n in pruned.nodes:
        flag = " <== FLAGGED SEED" if n["id"] == alert.get("event_id") else ""
        lines.append(f"  [{n['label']}] {n['name']!r}  id={n['id']}{flag}")

    lines.append("")
    lines.append(f"## 1-hop Edges ({len(pruned.edges)} kept)")
    for e in pruned.edges:
        lines.append(f"  {e['src'][:12]}..  --[{e['type']}]-->  {e['dst'][:12]}..")

    if pruned.collapsed:
        lines.append("")
        lines.append("## Repeated Patterns (collapsed)")
        for c in pruned.collapsed:
            src_lbl, etype, dst_lbl = c["signature"]
            samples = ", ".join(repr(s) for s in c["sample_dst_names"][:3])
            lines.append(
                f"  [{src_lbl}] --[{etype}]--> [{dst_lbl}]  × {c['count']} similar  e.g. {samples}"
            )

    elided_bits = [f"{k}={v}" for k, v in pruned.dropped.items() if v]
    if elided_bits:
        lines.append("")
        lines.append(f"## Elided\n  {', '.join(elided_bits)}")
        lines.append("  (LLM note: counts dropped to fit context; absence does not imply benignity)")

    return "\n".join(lines)
