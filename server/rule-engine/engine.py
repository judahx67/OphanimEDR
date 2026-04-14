"""
Rule-based matching engine.

Maintains a finite-state machine (FSM) per (rule_id, root_process_uuid).
Each incoming NormalizedEvent is tested against all in-progress FSM states.

State machine:
  - State 0..N-1 = how many conditions have been satisfied so far.
  - When state reaches len(rule.conditions), the rule fires.

Partial states expire after WINDOW_SECONDS to avoid stale matches.
"""

import re
import time
import uuid
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from loader import load_rules

log = logging.getLogger("rule-engine")

WINDOW_SECONDS = 300  # default causal window (overridden per-rule from YAML)


@dataclass
class PartialMatch:
    rule_id: str
    root_process_id: str   # UUID of the first subject that started the chain
    step: int              # number of conditions already satisfied
    last_event_ts: float   # wall-clock time of last advancement
    # Snapshot of matched edges so far (for subgraph in incident)
    matched_edges: list[dict[str, Any]] = field(default_factory=list)
    matched_nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    # The "active subject" — the process whose next action we're waiting for
    active_subject_id: str = ""


def _matches_condition(condition: dict, event: dict) -> bool:
    """Test whether a NormalizedEvent dict satisfies an EdgeCondition."""
    subj = event.get("subject", {})
    obj = event.get("object", {})

    # subject type
    if condition.get("subject_type"):
        if subj.get("node_type") != condition["subject_type"]:
            return False

    # subject name regex
    if condition.get("subject_name_re"):
        if not re.search(condition["subject_name_re"], subj.get("name", ""), re.IGNORECASE):
            return False

    # edge type (single string or list)
    if condition.get("edge_type") is not None:
        allowed = condition["edge_type"]
        if isinstance(allowed, str):
            allowed = [allowed]
        if event.get("edge_type") not in allowed:
            return False

    # object type
    if condition.get("object_type"):
        if obj.get("node_type") != condition["object_type"]:
            return False

    # object name regex
    if condition.get("object_name_re"):
        if not re.search(condition["object_name_re"], obj.get("name", ""), re.IGNORECASE):
            return False

    return True


def _node_snapshot(node_dict: dict) -> dict:
    return {
        "id": node_dict.get("id"),
        "type": node_dict.get("node_type"),
        "name": node_dict.get("name"),
    }


def _edge_snapshot(event: dict) -> dict:
    return {
        "event_id": event.get("event_id"),
        "edge_type": event.get("edge_type"),
        "subject_id": event.get("subject", {}).get("id"),
        "subject_name": event.get("subject", {}).get("name"),
        "object_id": event.get("object", {}).get("id"),
        "object_name": event.get("object", {}).get("name"),
        "timestamp": event.get("timestamp"),
    }


class RuleEngine:
    def __init__(self, rules_dir: str | None = None):
        self._rules_list = load_rules(rules_dir)
        self._rules = {r["id"]: r for r in self._rules_list}
        # Active partial matches:  (rule_id, root_process_id) -> PartialMatch
        self._states: dict[tuple[str, str], PartialMatch] = {}

    def _expire_old_states(self):
        now = time.time()
        expired = []
        for k, v in self._states.items():
            rule = self._rules.get(k[0])
            window = rule.get("window", WINDOW_SECONDS) if rule else WINDOW_SECONDS
            if now - v.last_event_ts > window:
                expired.append(k)
        for k in expired:
            del self._states[k]

    def process_event(self, event: dict) -> list[dict]:
        """
        Feed one NormalizedEvent into the engine.
        Returns a (possibly empty) list of fired incidents (as dicts).
        """
        self._expire_old_states()
        fired: list[dict] = []

        for rule in self._rules_list:
            conditions = rule["conditions"]
            n = len(conditions)
            subj_id = event.get("subject", {}).get("id", "")

            # --- Try to advance existing partial matches for this rule ---
            key = (rule["id"], subj_id)
            state = self._states.get(key)

            if state is not None and state.step < n:
                # The subject of this event must match the active subject
                if state.active_subject_id == subj_id or state.step == 0:
                    cond = conditions[state.step]
                    if _matches_condition(cond, event):
                        state.matched_edges.append(_edge_snapshot(event))
                        subj_node = event.get("subject", {})
                        obj_node = event.get("object", {})
                        if subj_node.get("id"):
                            state.matched_nodes[subj_node["id"]] = _node_snapshot(subj_node)
                        if obj_node.get("id"):
                            state.matched_nodes[obj_node["id"]] = _node_snapshot(obj_node)
                        state.step += 1
                        state.last_event_ts = time.time()
                        # Update active subject for next step
                        # If the matched object is a PROCESS, it becomes the new active subject
                        if obj_node.get("node_type") == "PROCESS":
                            state.active_subject_id = obj_node.get("id", subj_id)
                        else:
                            state.active_subject_id = subj_id

                        if state.step == n:
                            # Rule fired
                            incident = self._build_incident(rule, state, event)
                            fired.append(incident)
                            del self._states[key]

            # --- Try to start a new partial match from step 0 ---
            # (only if this event matches the first condition)
            if n > 0 and _matches_condition(conditions[0], event):
                new_key = (rule["id"], subj_id)
                if new_key not in self._states:
                    subj_node = event.get("subject", {})
                    obj_node = event.get("object", {})
                    nodes = {}
                    if subj_node.get("id"):
                        nodes[subj_node["id"]] = _node_snapshot(subj_node)
                    if obj_node.get("id"):
                        nodes[obj_node["id"]] = _node_snapshot(obj_node)

                    active = (
                        obj_node.get("id", subj_id)
                        if obj_node.get("node_type") == "PROCESS"
                        else subj_id
                    )

                    pm = PartialMatch(
                        rule_id=rule["id"],
                        root_process_id=subj_id,
                        step=1,
                        last_event_ts=time.time(),
                        matched_edges=[_edge_snapshot(event)],
                        matched_nodes=nodes,
                        active_subject_id=active,
                    )
                    if n == 1:
                        # Single-condition rule fires immediately
                        incident = self._build_incident(rule, pm, event)
                        fired.append(incident)
                    else:
                        self._states[new_key] = pm

        return fired

    def _build_incident(self, rule: dict, state: PartialMatch, event: dict) -> dict:
        incident_id = str(uuid.uuid4())
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()

        severity = rule["severity"]
        title = f"[{rule['mitre']}] {rule['name']}"
        if event.get("subject", {}).get("name"):
            title += f" — {event['subject']['name']}"

        return {
            "incident_id": incident_id,
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": severity,
            "status": "new",
            "title": title,
            "description": rule["description"],
            "mitre_technique": rule.get("mitre"),
            "endpoint_id": event.get("endpoint_id", "theia-e3"),
            "matched_nodes": json.dumps(list(state.matched_nodes.values())),
            "matched_edges": json.dumps(state.matched_edges),
            "rule_conditions": json.dumps(
                [c.get("edge_type", "?") for c in rule["conditions"]]
            ),
            "root_node_id": state.root_process_id,
            "confidence": 1.0,
            "created_at": now,
            "updated_at": now,
            "notes": "",
        }
