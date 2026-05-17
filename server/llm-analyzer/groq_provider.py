"""
Groq second-opinion provider.

Calls a Llama model on Groq's free tier (~30 req/min) using the same prompt
contract as Gemini. Returns the same (analysis_dict, raw_text, usage_dict)
shape so the cross-reference layer can compare them directly.

Why Groq: free tier is generous, latency is low (<500ms typical), and the
Llama family is a different lineage from Gemini — disagreement therefore
signals genuine ambiguity rather than shared training-corpus bias.

If GROQ_API_KEY is unset, the caller skips us entirely; we are pure opt-in.
"""
from __future__ import annotations

import json
import logging
import os
import time

logger = logging.getLogger("llm-analyzer.groq")

GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_PACING_SECONDS = float(os.environ.get("GROQ_PACING_SECONDS", "2.0"))


def is_enabled() -> bool:
    return bool(os.environ.get("GROQ_API_KEY"))


def make_client():
    """Lazy import so the container starts fine without the groq package
    installed at runtime (e.g. older image cached)."""
    from groq import Groq
    return Groq(api_key=os.environ["GROQ_API_KEY"])


def analyze(client, system_prompt: str, user_prompt: str) -> tuple[dict, str, dict]:
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                max_tokens=2048,
            )
            break
        except Exception as e:
            last_err = e
            msg = str(e).lower()
            if "rate" in msg or "429" in msg or "quota" in msg:
                wait = (2 ** attempt) * 5.0
                logger.warning("Groq rate-limited, retrying in %.1fs (%d/3)", wait, attempt + 1)
                time.sleep(wait)
                continue
            raise
    else:
        raise last_err  # type: ignore[misc]

    raw = response.choices[0].message.content or ""
    try:
        analysis = json.loads(raw)
    except json.JSONDecodeError:
        analysis = {"_parse_error": True, "raw": raw[:500]}

    u = response.usage
    usage = {
        "prompt_tokens": getattr(u, "prompt_tokens", 0) or 0,
        "output_tokens": getattr(u, "completion_tokens", 0) or 0,
        "total_tokens": getattr(u, "total_tokens", 0) or 0,
    }
    return analysis, raw, usage


def compare(primary: dict, secondary: dict) -> dict:
    """Compute agreement signals between two analyses.

    Returns a dict suitable to drop into the Incident node. Keep keys stable —
    the dashboard and downstream filters depend on them.
    """
    if not secondary or secondary.get("_parse_error"):
        return {"agreement_status": "secondary_unavailable"}

    def _norm_mitre(v):
        # Strip "T1059.001 - Whatever" → "T1059.001"
        if not v:
            return None
        s = str(v).split()[0].split("-")[0].strip()
        return s or None

    p_mitre = _norm_mitre(primary.get("mitre_technique"))
    s_mitre = _norm_mitre(secondary.get("mitre_technique"))

    if p_mitre and s_mitre:
        if p_mitre == s_mitre:
            mitre_agreement = "exact"
        elif p_mitre.split(".")[0] == s_mitre.split(".")[0]:
            # Same parent technique (T1059 vs T1059.001)
            mitre_agreement = "parent"
        else:
            mitre_agreement = "conflict"
    elif p_mitre or s_mitre:
        mitre_agreement = "one_null"
    else:
        mitre_agreement = "both_null"

    return {
        "agreement_status": mitre_agreement,
        "secondary_model": GROQ_MODEL,
        "secondary_mitre": s_mitre or "",
        "secondary_confidence": secondary.get("confidence") or "",
        "secondary_hypothesis": (secondary.get("attack_hypothesis") or "")[:240],
    }
