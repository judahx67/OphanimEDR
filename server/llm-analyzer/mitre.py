"""
MITRE ATT&CK technique selector.

Loads the curated technique subset (mitre_techniques.json) and picks the
candidates most relevant to an alert based on edge_type, sourcetype, and
keyword presence in subject/object names. The selected candidates are
injected into the LLM prompt so the model picks from an authoritative list
rather than guessing T-numbers.

Why curated, not full ATT&CK STIX: the official bundle is ~600 techniques
and would dominate the prompt. The curated subset covers every rule we
ship plus a handful of BOTSv2-relevant techniques not yet ruleified.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("llm-analyzer.mitre")

MAX_CANDIDATES = 6  # Hard cap on techniques injected into one prompt.


def load_techniques(path: str | Path | None = None) -> list[dict]:
    p = Path(path) if path else Path(__file__).parent / "mitre_techniques.json"
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    techniques = data.get("techniques", [])
    logger.info("Loaded %d MITRE technique candidates from %s", len(techniques), p.name)
    return techniques


def _score(technique: dict, edge_type: str, sourcetype: str, haystack: str) -> int:
    """Higher = more relevant. 0 means no trigger fired."""
    triggers = technique.get("triggers", {}) or {}
    score = 0
    if edge_type and edge_type in (triggers.get("edges") or []):
        score += 3
    if sourcetype and sourcetype in (triggers.get("sourcetypes") or []):
        score += 2
    for kw in (triggers.get("keywords") or []):
        if kw and kw.lower() in haystack:
            score += 2
    return score


def select_candidates(
    techniques: list[dict],
    alert: dict,
    subgraph: dict,
) -> list[dict]:
    """Pick up to MAX_CANDIDATES techniques most likely to apply.

    If no trigger matches anything (unusual alert), returns an empty list —
    the prompt then falls back to free-form MITRE guessing, which is the
    pre-Phase-5 behaviour.
    """
    edge_type = alert.get("edge_type", "") or ""
    sourcetype = alert.get("sourcetype", "") or ""

    # Haystack: subject/object names + names of all pruned subgraph nodes.
    parts: list[str] = []
    for side in ("subject", "object"):
        n = (alert.get(side) or {}).get("name", "") or ""
        parts.append(n)
    for n in subgraph.get("nodes", []):
        parts.append(n.get("name", "") or "")
    haystack = " ".join(parts).lower()

    scored = [(t, _score(t, edge_type, sourcetype, haystack)) for t in techniques]
    scored = [(t, s) for t, s in scored if s > 0]
    scored.sort(key=lambda ts: ts[1], reverse=True)
    return [t for t, _ in scored[:MAX_CANDIDATES]]


def format_candidates_for_prompt(candidates: list[dict]) -> str:
    """Render selected techniques as a compact prompt section."""
    if not candidates:
        return ""
    lines = ["## MITRE Candidates (pick from these IDs; if none fit, return null)"]
    for t in candidates:
        lines.append(
            f"  {t['id']} ({t['tactic']}) — {t['name']}: {t['desc']}"
        )
    return "\n".join(lines)
