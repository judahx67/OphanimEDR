"""Prompt + context builders for the Phase-B LLM features.

Kept separate from `llm_providers` (transport) and `main` (routing) so the
prompts — the part most likely to be tuned — live in one place.

Honesty discipline (CLAUDE.md): an L2 detector flag is an ANOMALY signal, not a
confirmed incident. The analysis prompt says so explicitly so the LLM narrative
never overclaims. The Sigma output feeds an integration demo (rule delivered to
Wazuh), never a live-detection claim.
"""
from __future__ import annotations

# ── Detection analysis (multi-LLM compare) ─────────────────────────────────

ANALYSIS_SYSTEM = """You are a SOC analyst assistant for a graph-based IDS system.

You are given a provenance subgraph around a node that an anomaly detector
flagged on the DARPA TC E3 THEIA dataset. The flag is an ANOMALY signal, NOT a
confirmed incident — treat it as a lead to triage, and say so if the evidence is
weak. Base your analysis ONLY on the provided subgraph.

Respond with JSON only (no prose, no code fences):
{
  "attack_hypothesis": "one sentence on the most likely behaviour (or 'likely benign' if so)",
  "mitre_technique": "e.g. T1059 (or null if unclear)",
  "mitre_tactic": "e.g. Execution (or null)",
  "evidence_summary": "2-3 specific indicators from the subgraph",
  "confidence": "high | medium | low",
  "false_positive_risk": "high | medium | low",
  "analyst_action": "one concrete next step for a human analyst"
}
Be concise and precise."""


def subgraph_to_text(node: dict, subgraph: dict, max_edges: int = 25) -> str:
    """Render a flagged node + its 1-hop neighbourhood as compact LLM context."""
    nodes = subgraph.get("nodes", [])
    edges = subgraph.get("edges", [])
    name_by_id = {n["id"]: (n.get("name") or n["id"]) for n in nodes}
    uuid = node.get("uuid") or node.get("id", "")

    lines = ["## Flagged node"]
    lines.append(f"  uuid : {uuid}")
    lines.append(f"  type : {node.get('label', '?')}")
    lines.append(f"  name : {node.get('name') or uuid}")
    flags = []
    if node.get("flash_seed"):
        flags.append("FLASH (GraphSAGE)")
    if node.get("orthrus_seed"):
        flags.append("Orthrus (GAT recon)")
    if flags:
        lines.append(f"  flagged by : {', '.join(flags)}")
    if node.get("orthrus_score") is not None:
        lines.append(f"  orthrus recon score : {node['orthrus_score']:.4f}")

    lines.append("")
    lines.append(f"## Subgraph ({len(nodes)} nodes, {len(edges)} edges)")
    # A flagged node can have hundreds of edges dominated by repetitive,
    # low-signal actions (MMAP/READ) and a null-UUID hub. A naive first-N slice
    # buries the smoking guns (a `uname -a` fork, socket C2). So: drop the null
    # hub, collapse identical edges to a count, and rank high-signal actions
    # first — the LLM sees `FORK -> uname -a (x2)` and CONNECT/SEND before MMAP.
    NULL_UUID = "00000000-0000-0000-0000-000000000000"
    SIGNAL_RANK = {
        "EXEC": 0, "EXECUTE": 0, "FORK": 1, "CONNECT": 2, "SEND": 3,
        "RECEIVE": 4, "WRITE": 5, "DELETE": 5, "LOAD": 6, "MODIFY_REG": 6,
        "RENAME": 7, "READ": 8, "MMAP": 9, "MPROTECT": 9, "ACCESS": 9,
    }
    grouped: dict[tuple, int] = {}
    for e in edges:
        src_id, dst_id = e.get("source", ""), e.get("target", "")
        other = dst_id if src_id == uuid else src_id
        if other.startswith(NULL_UUID):  # carries no information
            continue
        src = name_by_id.get(src_id, src_id)[:48]
        dst = name_by_id.get(dst_id, dst_id)[:48]
        key = (src, e.get("type", "?"), dst)
        grouped[key] = grouped.get(key, 0) + 1
    ordered = sorted(
        grouped.items(),
        key=lambda kv: (SIGNAL_RANK.get(kv[0][1], 9), -kv[1]),
    )
    for (src, etype, dst), cnt in ordered[:max_edges]:
        suffix = f"  (x{cnt})" if cnt > 1 else ""
        lines.append(f"  {src}  --[{etype}]-->  {dst}{suffix}")
    if len(ordered) > max_edges:
        lines.append(f"  ... +{len(ordered) - max_edges} more distinct edges (omitted)")
    return "\n".join(lines)


def analysis_user_prompt(node: dict, subgraph: dict) -> str:
    return "Triage this flagged provenance node:\n\n" + subgraph_to_text(node, subgraph)


# ── Sigma rule generation (SIEM export) ────────────────────────────────────

SIGMA_SYSTEM = """You are a detection engineer. Given an incident (or a node
flagged by an anomaly detector) and its provenance context, write ONE Sigma
rule that would catch this pattern on a Linux endpoint.

Output ONLY valid Sigma YAML — no prose, no markdown code fences. Use these keys:
  title:        short, specific
  status:       experimental
  description:  one sentence
  logsource:    {product: linux, category: process_creation}
  detection:    a `selection` mapping (field -> value or list) + `condition: selection`
  level:        one of informational | low | medium | high | critical
  tags:         list including the MITRE technique as attack.tXXXX when known

Base the selection on stable artefacts from the context (process names, file
paths, command patterns) — not on volatile values (IPs, timestamps, ports)."""


def incident_to_context(inc: dict) -> str:
    """Render an incident (+ its matched edges) as context for Sigma generation."""
    lines = ["## IDS incident"]
    lines.append(f"  rule         : {inc.get('rule_name', '?')}")
    if inc.get("mitre_technique"):
        lines.append(f"  mitre        : {inc['mitre_technique']}")
    lines.append(f"  severity     : {_enum(inc.get('severity', 'medium'))}")
    if inc.get("title"):
        lines.append(f"  title        : {inc['title']}")
    if inc.get("description"):
        lines.append(f"  description  : {inc['description']}")

    edges = inc.get("matched_edges") or []
    if edges:
        lines.append("")
        lines.append(f"## Matched provenance edges ({len(edges)})")
        for e in edges[:20]:
            if not isinstance(e, dict):
                continue
            subj = e.get("subject_name") or e.get("subject_id") or "?"
            obj = e.get("object_name") or e.get("object_id") or "?"
            lines.append(f"  {subj}  --[{e.get('edge_type', '?')}]-->  {obj}")
    return "\n".join(lines)


def _enum(v: object) -> str:
    v = getattr(v, "value", v)
    return str(v).split(".")[-1].lower()
