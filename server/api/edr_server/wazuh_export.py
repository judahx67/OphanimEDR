"""Sigma-rule export to the Wazuh SIEM.

The platform's "feedback loop": a confirmed L1 incident is turned into a Sigma
rule, converted to Wazuh's native XML, pushed to the Wazuh manager over its REST
API, and read back to prove it arrived. This is an *integration* demonstration —
the rule is delivered and accepted by the SIEM; we make no live-detection or
blocking claim (the manager only activates it on reload, out of scope here).

Now the Sigma rule is built from the incident with a deterministic template; the
Phase-B LLM step replaces `incident_to_sigma` with a generated rule, feeding the
same convert→push→verify path unchanged.
"""

import hashlib
import os
import re
from typing import Optional
from xml.sax.saxutils import escape

import httpx
import yaml

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://wazuh-manager:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "wazuh")

# Sigma severity word -> Wazuh numeric level (0-15).
_LEVEL = {"critical": 14, "high": 12, "medium": 7, "low": 4, "informational": 3}
# Wazuh custom rules must live in the 100000+ id space.
_RULE_ID_BASE = 100000
_RULE_ID_SPAN = 9000


def _rule_id(seed: str) -> int:
    h = int(hashlib.sha1(seed.encode()).hexdigest(), 16)
    return _RULE_ID_BASE + (h % _RULE_ID_SPAN)


def _ascii(s: object, limit: int = 250) -> str:
    """ASCII-safe one-line string (drops mojibake em-dashes etc.)."""
    return str(s).encode("ascii", "ignore").decode().replace("\n", " ").strip()[:limit]


def _enum_value(v: object) -> str:
    """'IncidentSeverity.critical' / enum -> 'critical'."""
    v = getattr(v, "value", v)
    return str(v).split(".")[-1].lower()


def incident_to_sigma(inc: dict) -> dict:
    """Deterministic incident -> Sigma rule (Phase-B LLM swaps this out)."""
    rule_name = inc.get("rule_name") or "edr_detection"
    mitre = inc.get("mitre_technique")
    tags = [f"attack.{mitre.lower()}"] if mitre else []
    # Clean Sigma selection from the matched edge chain: the event types and the
    # acting process — not raw edge dicts.
    edges = inc.get("matched_edges") or []
    etypes = sorted({e.get("edge_type") for e in edges
                     if isinstance(e, dict) and e.get("edge_type")})
    actors = sorted({e.get("subject_name") for e in edges
                     if isinstance(e, dict) and e.get("subject_name")})
    selection: dict = {}
    if etypes:
        selection["EventType"] = etypes
    if actors:
        selection["Image|contains"] = actors if len(actors) > 1 else actors[0]
    if not selection:
        selection = {"rule": rule_name}
    return {
        "title": _ascii(inc.get("title") or rule_name),
        "id": inc.get("incident_id") or rule_name,
        "status": "experimental",
        "description": _ascii(inc.get("description")
                              or f"Exported from EDR incident '{rule_name}'"),
        "level": _enum_value(inc.get("severity") or "medium"),
        "logsource": {"product": "linux", "category": "process_creation"},
        "detection": {"selection": selection, "condition": "selection"},
        "tags": tags,
    }


def sigma_to_wazuh_xml(sigma: dict, rule_id: int) -> str:
    """Minimal but valid Wazuh-XML rule for the given Sigma dict.

    Fidelity of the match logic is secondary — the goal is a well-formed rule the
    manager accepts. Each Sigma selection field becomes a <field> matcher.
    """
    level = _LEVEL.get(_enum_value(sigma.get("level", "medium")), 7)
    desc = escape(_ascii(sigma.get("description") or sigma.get("title") or "EDR rule"))
    detection = sigma.get("detection", {}) or {}

    fields: list[tuple[str, str]] = []
    for key, block in detection.items():
        if key == "condition" or not isinstance(block, dict):
            continue
        for fk, fv in block.items():
            name = re.sub(r"[^A-Za-z0-9_]", "_", fk.split("|")[0]) or "data"
            for val in (fv if isinstance(fv, list) else [fv]):
                fields.append((name, escape(_ascii(val, 200))))
    if not fields:
        fields = [("data", "EDR_EXPORT")]

    field_xml = "".join(f'\n    <field name="{n}">{v}</field>' for n, v in fields)
    mitre_ids = [
        t.split(".")[-1].upper() for t in sigma.get("tags", [])
        if str(t).lower().startswith("attack.t")
    ]
    mitre_xml = (
        "\n    <mitre>" + "".join(f"<id>{escape(m)}</id>" for m in mitre_ids) + "</mitre>"
        if mitre_ids else ""
    )
    return (
        '<group name="sigma,edr_export,">\n'
        f'  <rule id="{rule_id}" level="{level}">\n'
        f'    <description>{desc}</description>'
        f'{field_xml}{mitre_xml}\n'
        '    <options>no_full_log</options>\n'
        '  </rule>\n'
        '</group>\n'
    )


class WazuhClient:
    def __init__(self, base: str = WAZUH_API_URL, user: str = WAZUH_API_USER,
                 pw: str = WAZUH_API_PASS):
        self.base, self.user, self.pw = base.rstrip("/"), user, pw

    async def push_and_verify(self, filename: str, xml: str) -> dict:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as c:
            tok = await c.post(f"{self.base}/security/user/authenticate?raw=true",
                               auth=(self.user, self.pw))
            tok.raise_for_status()
            h = {"Authorization": f"Bearer {tok.text.strip()}"}
            put = await c.put(
                f"{self.base}/rules/files/{filename}?overwrite=true",
                content=xml.encode(),
                headers={**h, "Content-Type": "application/octet-stream"},
            )
            put_json = put.json() if put.headers.get("content-type", "").startswith("application/json") else {}
            # Read it back from the manager: proof it arrived and is stored.
            get = await c.get(f"{self.base}/rules/files/{filename}", headers=h)
            wazuh_err = (put_json.get("error", 1) not in (0, None))
            return {
                "put_status": put.status_code,
                "wazuh_response": put_json,
                "verify_status": get.status_code,
                "accepted": put.status_code in (200, 201) and not wazuh_err,
                "verified": get.status_code == 200,
            }


async def export_incident_rule(inc: dict, sigma_override: Optional[str] = None) -> dict:
    """Build (or accept) a Sigma rule for an incident, push to Wazuh, verify."""
    sigma = yaml.safe_load(sigma_override) if sigma_override else incident_to_sigma(inc)
    rid = _rule_id(str(sigma.get("id") or inc.get("incident_id") or "edr"))
    xml = sigma_to_wazuh_xml(sigma, rid)
    filename = f"edr_export_{rid}.xml"
    result = await WazuhClient().push_and_verify(filename, xml)
    return {
        "ok": result["accepted"] and result["verified"],
        "rule_id": rid,
        "filename": filename,
        "sigma": sigma,
        "wazuh_xml": xml,
        **result,
    }
