"""
YAML rule loader — Sigma-inspired format for provenance graph rules.

Parses .yml files from a rules directory into the internal dict format
consumed by the FSM engine.

Supports two detection modes:
  - selection:  single-edge match (fires on one event)
  - sequence:   ordered causal chain with a time window

YAML schema (see rules/*.yml for examples):
  title, id, severity, description, tags, logsource,
  detection:
    selection: { subject, edge, object }          # single-step
    sequence:  { window, ordered, steps: [...] }  # multi-step
    condition: "selection" | "sequence"
"""

import logging
import os
import re
from pathlib import Path

import yaml

log = logging.getLogger("rule-engine")


def _parse_node_spec(node: dict | None) -> tuple[str | None, str | None]:
    """Extract (node_type, name_regex) from a YAML node block."""
    if not node:
        return None, None
    node_type = node.get("type")
    # Look for name|re key (Sigma modifier syntax)
    name_re = node.get("name|re")
    return node_type, name_re


def _parse_edge_spec(edge) -> str | list[str] | None:
    """Edge can be a string, a list of strings, or None."""
    if edge is None:
        return None
    if isinstance(edge, list):
        return edge
    return str(edge)


def _parse_step(step_dict: dict) -> dict:
    """Convert a single YAML step/selection into an EdgeCondition dict."""
    subject_type, subject_name_re = _parse_node_spec(step_dict.get("subject"))
    object_type, object_name_re = _parse_node_spec(step_dict.get("object"))
    edge_type = _parse_edge_spec(step_dict.get("edge"))

    return {
        "subject_type": subject_type,
        "subject_name_re": subject_name_re,
        "edge_type": edge_type,
        "object_type": object_type,
        "object_name_re": object_name_re,
    }


def _extract_mitre(tags: list[str] | None) -> str | None:
    """Pull the first ATT&CK technique ID from Sigma-style tags."""
    if not tags:
        return None
    for tag in tags:
        m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", tag, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None


def load_rule(filepath: str | Path) -> dict:
    """Parse one YAML rule file into the engine's internal dict format."""
    path = Path(filepath)
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        raise ValueError(f"Empty or invalid rule file: {path}")

    detection = raw.get("detection", {})
    condition = detection.get("condition", "")

    # Build conditions list from either sequence or selection
    conditions = []
    window = 300  # default 5 minutes

    if condition == "sequence" and "sequence" in detection:
        seq = detection["sequence"]
        window = seq.get("window", 300)
        for step in seq.get("steps", []):
            # Each step is a dict with one key (step name) -> value (edge spec)
            for _step_name, step_spec in step.items():
                conditions.append(_parse_step(step_spec))

    elif condition == "selection" and "selection" in detection:
        conditions.append(_parse_step(detection["selection"]))

    else:
        raise ValueError(
            f"Rule {path.name}: condition must be 'selection' or 'sequence', "
            f"got '{condition}'"
        )

    mitre = _extract_mitre(raw.get("tags"))

    return {
        "id": raw["id"],
        "name": raw.get("title", raw["id"]),
        "severity": raw.get("severity", "medium"),
        "mitre": mitre,
        "description": raw.get("description", ""),
        "conditions": conditions,
        "window": window,
        # Extra metadata preserved for API / dashboard
        "tags": raw.get("tags", []),
        "falsepositives": raw.get("falsepositives", []),
        "references": raw.get("references", []),
        "author": raw.get("author", ""),
        "status": raw.get("status", "experimental"),
    }


def load_rules(rules_dir: str | Path = None) -> list[dict]:
    """Load all .yml rules from the given directory."""
    if rules_dir is None:
        # Default: rules/ subdirectory next to this file
        rules_dir = Path(__file__).parent / "rules"

    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        log.warning("Rules directory not found: %s", rules_dir)
        return []

    rules = []
    for yml_file in sorted(rules_dir.glob("*.yml")):
        try:
            rule = load_rule(yml_file)
            rules.append(rule)
            log.info("Loaded rule: %s (%s)", rule["id"], yml_file.name)
        except Exception as exc:
            log.error("Failed to load rule %s: %s", yml_file.name, exc)

    log.info("Loaded %d rules from %s", len(rules), rules_dir)
    return rules
