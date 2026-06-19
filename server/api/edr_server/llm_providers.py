"""Unified multi-provider LLM client for on-demand analysis (api service).

Two interactive Phase-B features call this synchronously from FastAPI endpoints:
  - POST /api/compare/llm          — same detection, multiple LLMs side by side
  - POST /api/wazuh/generate-sigma — an LLM-authored Sigma rule for a SIEM export

Every provider exposes the SAME contract: given (system, user) prompts it returns
a dict {provider, model, raw, analysis?, error}. The official SDKs are synchronous,
so each call is wrapped in asyncio.to_thread to avoid blocking the event loop.

Models default to the cheap tier (cost-capped demo); override per provider via env.
The Anthropic call follows the `claude-api` skill (anthropic SDK, messages.create).
"""
from __future__ import annotations

import asyncio
import json
import os

# Canonical provider order; the dashboard renders columns in this order.
# Gemini dropped — every available key's project had zero free-tier quota
# (429 RESOURCE_EXHAUSTED, limit: 0). Groq/Anthropic/OpenAI are the live set.
PROVIDERS = ("groq", "anthropic", "openai")

# Cheap models — the demo is cost-sensitive, not benchmarking the LLMs.
MODELS = {
    "gemini": os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"),
    "groq": os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
    "anthropic": os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5"),
    "openai": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
}
# Premium tier — opt-in, frontier models, used "extremely sparingly". Only the
# paid providers have a premium model; gemini/groq stay on their free tier.
PREMIUM_MODELS = {
    "anthropic": os.environ.get("ANTHROPIC_PREMIUM_MODEL", "claude-opus-4-8"),
    "openai": os.environ.get("OPENAI_PREMIUM_MODEL", "gpt-5.5"),
}
ENV_KEY = {
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}

LABELS = {
    "gemini": "Gemini",
    "groq": "Groq (Llama)",
    "anthropic": "Claude",
    "openai": "OpenAI (GPT)",
}

# ── Budget guards ───────────────────────────────────────────────────────────
# The OpenAI key is uncapped, so a runaway loop could rack up real money. These
# are HARD, in-process ceilings: once hit, calls are refused (not retried).
# Counters reset on container restart — small ceilings bound any single run.
# `gpt-5.5` / `claude-opus-4-8` are the expensive ones, so premium has its own,
# tighter ceiling on top of the per-provider OpenAI one.
OPENAI_CALL_BUDGET = int(os.environ.get("OPENAI_CALL_BUDGET", "40"))
PREMIUM_CALL_BUDGET = int(os.environ.get("PREMIUM_CALL_BUDGET", "15"))
MAX_TOKENS_CAP = int(os.environ.get("LLM_MAX_TOKENS_CAP", "1200"))

_usage = {"openai": 0, "premium": 0}


def budget_status() -> dict:
    """Remaining safeguard budget — surfaced to the UI so it's visible, not silent."""
    return {
        "openai_calls_used": _usage["openai"],
        "openai_call_budget": OPENAI_CALL_BUDGET,
        "premium_calls_used": _usage["premium"],
        "premium_call_budget": PREMIUM_CALL_BUDGET,
        "premium_models": PREMIUM_MODELS,
    }


def available() -> dict[str, bool]:
    """Which providers have an API key configured (for the UI to grey out)."""
    return {p: bool(os.environ.get(ENV_KEY[p])) for p in PROVIDERS}


def has_premium(provider: str) -> bool:
    return provider in PREMIUM_MODELS and bool(os.environ.get(ENV_KEY[provider]))


def extract_json(raw: str) -> dict:
    """Best-effort parse of a JSON object from an LLM response (handles fences)."""
    s = (raw or "").strip()
    if "```" in s:
        for part in s.split("```"):
            chunk = part.strip()
            if chunk.startswith("json"):
                chunk = chunk[4:].strip()
            if chunk.startswith("{"):
                s = chunk
                break
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return {"_parse_error": True, "raw": (raw or "")[:600]}


def strip_code_fence(raw: str, lang: str = "yaml") -> str:
    """Return the body of a fenced block (```lang ... ```), else the raw text."""
    s = (raw or "").strip()
    if "```" not in s:
        return s
    for part in s.split("```"):
        chunk = part.strip()
        if chunk.lower().startswith(lang):
            chunk = chunk[len(lang):].strip()
        if chunk and not chunk.lower().startswith(("here", "this", "the ")):
            return chunk
    return s


# ── Per-provider synchronous calls (lazy SDK imports) ───────────────────────

def _call_gemini(model: str, system: str, user: str, max_tokens: int) -> str:
    from google import genai
    from google.genai import types as genai_types

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    cfg = genai_types.GenerateContentConfig(
        system_instruction=system, max_output_tokens=max_tokens,
    )
    resp = client.models.generate_content(model=model, contents=user, config=cfg)
    return (resp.text or "").strip()


def _call_groq(model: str, system: str, user: str, max_tokens: int) -> str:
    from groq import Groq

    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        max_tokens=max_tokens,
    )
    return (resp.choices[0].message.content or "").strip()


def _call_openai(model: str, system: str, user: str, max_tokens: int) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    # The GPT-5 / o-series models renamed the cap to `max_completion_tokens`
    # and reject the legacy `max_tokens`; gpt-4o still uses the old name.
    m = model.lower()
    token_kw = ("max_completion_tokens"
                if m.startswith("gpt-5") or m.startswith("o")
                else "max_tokens")
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        **{token_kw: max_tokens},
    )
    return (resp.choices[0].message.content or "").strip()


def _call_anthropic(model: str, system: str, user: str, max_tokens: int) -> str:
    import anthropic

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    resp = client.messages.create(
        model=model, max_tokens=max_tokens, system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(b.text for b in resp.content if b.type == "text").strip()


_DISPATCH = {
    "gemini": _call_gemini,
    "groq": _call_groq,
    "anthropic": _call_anthropic,
    "openai": _call_openai,
}


async def call_llm(
    provider: str, system: str, user: str,
    max_tokens: int = 800, want_json: bool = True, premium: bool = False,
) -> dict:
    """Call one provider; never raises — errors come back in the `error` field.

    `premium=True` swaps in the frontier model for paid providers, subject to the
    in-process budget ceilings. Budget refusals are returned as `error`, not raised.
    """
    is_premium = premium and provider in PREMIUM_MODELS
    model = PREMIUM_MODELS[provider] if is_premium else MODELS.get(provider)
    out: dict = {"provider": provider, "label": LABELS.get(provider, provider),
                 "model": model, "premium": is_premium, "raw": "", "error": None}

    if provider not in _DISPATCH:
        out["error"] = f"unknown provider '{provider}'"
        return out
    if not os.environ.get(ENV_KEY[provider]):
        out["error"] = f"{ENV_KEY[provider]} not configured"
        return out

    # Budget guards — refuse before spending. Premium has its own tighter ceiling.
    if is_premium and _usage["premium"] >= PREMIUM_CALL_BUDGET:
        out["error"] = f"premium budget exhausted ({PREMIUM_CALL_BUDGET} calls/run); restart api to reset"
        return out
    if provider == "openai" and _usage["openai"] >= OPENAI_CALL_BUDGET:
        out["error"] = f"OpenAI budget exhausted ({OPENAI_CALL_BUDGET} calls/run); restart api to reset"
        return out

    # Charge the budget up front so a crash mid-call still counts against it.
    if provider == "openai":
        _usage["openai"] += 1
    if is_premium:
        _usage["premium"] += 1

    capped = min(int(max_tokens), MAX_TOKENS_CAP)
    try:
        raw = await asyncio.to_thread(_DISPATCH[provider], model, system, user, capped)
    except Exception as e:  # noqa: BLE001
        # Premium model unavailable/errored → fall back ONCE to the cheap model
        # (e.g. gpt-5.5 not enabled on the key → gpt-4o-mini). Bounded: one retry.
        cheap = MODELS.get(provider)
        if is_premium and cheap and cheap != model:
            try:
                raw = await asyncio.to_thread(_DISPATCH[provider], cheap, system, user, capped)
                out["model"] = cheap
                out["premium"] = False
                out["fallback_from"] = model
            except Exception as e2:  # noqa: BLE001
                out["error"] = f"{type(e2).__name__}: {e2}"
                return out
        else:
            out["error"] = f"{type(e).__name__}: {e}"
            return out
    out["raw"] = raw
    if want_json:
        out["analysis"] = extract_json(raw)
    return out
