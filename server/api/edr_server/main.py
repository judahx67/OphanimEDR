"""FastAPI application — EDR API (Neo4j backend)."""

from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import __version__
from . import llm_providers, llm_prompts
from .wazuh_export import export_incident_rule
from .database import (
    connect_db,
    close_db,
    get_graph_stats,
    get_graph_endpoints,
    get_incidents,
    get_incident,
    get_incident_stats,
    update_incident_status,
    get_node_subgraph,
    get_recent_edges,
    get_ml_scores,
    get_ml_summary,
    get_ml_edge_findings,
    get_ml_edge_by_event_id,
    get_ml_edge_summary,
    get_llm_incident,
    get_detector_summary,
    get_detector_comparison,
    save_node_llm_analysis,
    get_node_llm_analyses,
)
from .models import (
    GraphStats,
    HealthResponse,
    IncidentInDB,
    IncidentListResponse,
    IncidentStats,
    IncidentStatus,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title="IDS Server",
    description="Graph-based IDS API — reads from Neo4j provenance graph.",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    return HealthResponse(status="healthy", version=__version__, database="neo4j")


# ---------------------------------------------------------------------------
# Graph stats  (feeds dashboard overview cards)
# ---------------------------------------------------------------------------

@app.get("/api/graph/endpoints", tags=["Graph"])
async def graph_endpoints():
    """Per-endpoint summary derived from the provenance graph."""
    return await get_graph_endpoints()


@app.get("/api/graph/stats", response_model=GraphStats, tags=["Graph"])
async def graph_stats():
    """Node/edge counts from the Neo4j provenance graph."""
    return await get_graph_stats()


@app.get("/api/graph/recent-edges", tags=["Graph"])
async def recent_edges(limit: int = Query(100, ge=1, le=1000)):
    """Most recent edges in the graph, ordered by timestamp desc."""
    return await get_recent_edges(limit=limit)


@app.get("/api/graph/subgraph/{node_id:path}", tags=["Graph"])
async def node_subgraph(node_id: str, hops: int = Query(2, ge=1, le=4)):
    """K-hop neighbourhood of a provenance node (for graph explorer).

    Uses :path converter so node_ids containing forward slashes (e.g.
    'sock:host:port->host:port/tcp') are matched as a single parameter.
    Query strings ('?') in node_ids must still be URL-encoded by the caller.
    """
    result = await get_node_subgraph(node_id, hops=hops)
    if not result["nodes"]:
        raise HTTPException(status_code=404, detail="Node not found")
    return result


@app.get("/api/graph/subgraph", tags=["Graph"])
async def node_subgraph_by_query(
    node_id: list[str] = Query(..., description="Provenance node UUID(s). Pass repeatedly to include multiple roots."),
    hops: int = Query(2, ge=1, le=4),
):
    """K-hop neighbourhood around one or more root nodes.

    Pass `?node_id=...&node_id=...` to merge the neighbourhoods of multiple
    roots — typically the subject and object of a flagged edge, which gives a
    fuller picture than the subject alone for socket-to-socket edges.
    """
    merged_nodes: dict[str, dict] = {}
    merged_edges: dict[str, dict] = {}
    for nid in node_id:
        result = await get_node_subgraph(nid, hops=hops)
        for n in result["nodes"]:
            merged_nodes.setdefault(n["id"], n)
        for e in result["edges"]:
            key = e.get("event_id") or f"{e['source']}|{e['target']}|{e['type']}"
            merged_edges.setdefault(key, e)
    if not merged_nodes:
        raise HTTPException(status_code=404, detail="No nodes found for provided id(s)")
    return {"nodes": list(merged_nodes.values()), "edges": list(merged_edges.values())}


# ---------------------------------------------------------------------------
# Incidents  (output of the rule engine)
# ---------------------------------------------------------------------------

@app.get("/api/incidents", response_model=IncidentListResponse, tags=["Incidents"])
async def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    skip = (page - 1) * page_size
    incidents, total = await get_incidents(
        status=status,
        severity=severity,
        rule_id=rule_id,
        search=search,
        limit=page_size,
        skip=skip,
    )
    return IncidentListResponse(
        incidents=incidents, total=total, page=page, page_size=page_size
    )


@app.get("/api/incidents/stats", tags=["Incidents"])
async def incident_statistics():
    """Counts by status and severity."""
    return await get_incident_stats()


@app.get("/api/incidents/{incident_id}", response_model=IncidentInDB, tags=["Incidents"])
async def get_incident_detail(incident_id: str):
    incident = await get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.patch("/api/incidents/{incident_id}/status", tags=["Incidents"])
async def update_status(
    incident_id: str,
    status: IncidentStatus = Query(...),
    notes: str = Query(""),
):
    success = await update_incident_status(incident_id, status, notes)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"success": True, "status": status.value}


# ---------------------------------------------------------------------------
# ML scores  (output of the ml-engine batch job)
# ---------------------------------------------------------------------------

@app.get("/api/ml/scores", tags=["ML"])
async def ml_scores(limit: int = Query(100, ge=1, le=1000)):
    """Top-N Process nodes ranked by ml_score."""
    return await get_ml_scores(limit=limit)


@app.get("/api/ml/summary", tags=["ML"])
async def ml_summary():
    """Aggregate stats on ml_score distribution across Process nodes."""
    return await get_ml_summary()


@app.get("/api/ml/edges/top", tags=["ML"])
async def ml_edge_findings(
    rule_clear: bool = Query(True, description="Only return edges with no rule-engine Incident"),
    limit: int = Query(50, ge=1, le=500),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    analysis: str = Query(
        "any",
        regex="^(any|ok|any_attempt|none)$",
        description=(
            "Filter by LLM analysis status. "
            "'any' = no filter, "
            "'ok' = LLM produced parseable JSON (hides parse-errors), "
            "'any_attempt' = analyser ran (ok or failed), "
            "'none' = no LLM analysis yet."
        ),
    ),
):
    """
    Top-scoring edges from the ml-edge-scorer.

    rule_clear=true (default): only edges NOT flagged by any rule-engine Incident.
    This is the headline thesis query — 'what did ML find that rules missed?'
    Each row carries an `analysis_status` field for client-side rendering.
    """
    return await get_ml_edge_findings(
        rule_clear=rule_clear, limit=limit, min_score=min_score, analysis=analysis,
    )


@app.get("/api/ml/edges/by-id/{event_id}", tags=["ML"])
async def ml_edge_by_id(event_id: str):
    """
    Fetch a single ML-scored edge by exact event_id, bypassing the
    top-N dedup applied by `/api/ml/edges/top`. Useful for UI lookup
    of a specific event_id (e.g. one referenced in an LLM narrative)
    that may have been collapsed under a sibling representative.
    """
    result = await get_ml_edge_by_event_id(event_id)
    if not result:
        raise HTTPException(status_code=404, detail="No scored edge with this event_id")
    return result


@app.get("/api/ml/edges/summary", tags=["ML"])
async def ml_edge_summary():
    """Aggregate stats on botsv2_ml_score distribution across all scored edges."""
    return await get_ml_edge_summary()


@app.get("/api/ml/incidents/{event_id}", tags=["ML"])
async def ml_llm_incident(event_id: str):
    """
    Fetch the LLM-generated narrative for a flagged edge by event_id.
    Written by the llm-analyzer service.
    """
    result = await get_llm_incident(event_id)
    if not result:
        raise HTTPException(status_code=404, detail="No LLM narrative found for this event_id")
    return result


# ---------------------------------------------------------------------------
# Detector comparison  (FLASH GNN vs Orthrus on the same THEIA graph)
# ---------------------------------------------------------------------------

@app.get("/api/compare/summary", tags=["Compare"])
async def compare_summary():
    """Per-label scored/seed counts for FLASH and Orthrus on the shared graph.

    The per-label breakdown is the head-to-head: FLASH floods the abundant
    node type while flagging 0 Process; Orthrus (once active) flags few/precise.
    `orthrus_active` is false until the orthrus scorer has written its props.
    """
    return await get_detector_summary()


@app.get("/api/compare/detectors", tags=["Compare"])
async def compare_detectors(
    limit: int = Query(200, ge=1, le=2000),
    seeds_only: bool = Query(True, description="Only nodes flagged by ≥1 detector"),
):
    """Per-node FLASH-vs-Orthrus verdicts on the shared THEIA provenance graph."""
    return await get_detector_comparison(limit=limit, seeds_only=seeds_only)


# ---------------------------------------------------------------------------
# Multi-LLM analysis  (Phase B — side-by-side narratives for a flagged node)
# ---------------------------------------------------------------------------

# Per-request cap on top of the in-process budget guards in llm_providers.
_MAX_LLM_CALLS_PER_REQUEST = 8


@app.get("/api/llm/providers", tags=["LLM"])
async def llm_providers_status():
    """Which providers are usable + remaining budget (for the compare UI)."""
    return {
        "providers": llm_providers.PROVIDERS,
        "labels": llm_providers.LABELS,
        "available": llm_providers.available(),
        "premium_available": {p: llm_providers.has_premium(p) for p in llm_providers.PROVIDERS},
        "models": llm_providers.MODELS,
        "budget": llm_providers.budget_status(),
    }


class LLMCompareRequest(BaseModel):
    node_ids: list[str]                 # 1-2 flagged node UUIDs
    providers: list[str]                # 1-4 provider names
    premium: bool = False              # opt-in frontier models (budget-guarded)


@app.post("/api/compare/llm", tags=["LLM"])
async def compare_llm(req: LLMCompareRequest):
    """Run the SAME flagged node(s) through several LLMs for a side-by-side read.

    The detector flag is an anomaly signal; this surfaces how different models
    narrate the same provenance context — a teaching artifact, no ground truth.
    """
    node_ids = [n for n in dict.fromkeys(req.node_ids) if n][:2]
    provs = [p for p in dict.fromkeys(req.providers) if p in llm_providers.PROVIDERS][:4]
    if not node_ids or not provs:
        raise HTTPException(status_code=400, detail="Provide 1-2 node_ids and 1-4 known providers")
    if len(node_ids) * len(provs) > _MAX_LLM_CALLS_PER_REQUEST:
        raise HTTPException(
            status_code=400,
            detail=f"Too many calls ({len(node_ids)}×{len(provs)}); cap is {_MAX_LLM_CALLS_PER_REQUEST}",
        )

    # Build each node's context once, then fan out across providers concurrently.
    contexts: list[tuple[dict, str]] = []
    for nid in node_ids:
        sub = await get_node_subgraph(nid, hops=1)
        if not sub["nodes"]:
            raise HTTPException(status_code=404, detail=f"Node not found: {nid}")
        root = next((n for n in sub["nodes"] if n["id"] == nid), {"id": nid})
        node_meta = {"uuid": nid, "label": root.get("label"), "name": root.get("name")}
        contexts.append((node_meta, llm_prompts.analysis_user_prompt(node_meta, sub)))

    import asyncio
    tasks, meta = [], []
    for node_meta, user_prompt in contexts:
        for prov in provs:
            tasks.append(llm_providers.call_llm(
                prov, llm_prompts.ANALYSIS_SYSTEM, user_prompt,
                max_tokens=800, want_json=True, premium=req.premium,
            ))
            meta.append(node_meta)
    raw_results = await asyncio.gather(*tasks)
    results = [{"node_id": m["uuid"], "node_name": m.get("name"),
                "node_label": m.get("label"), **r} for m, r in zip(meta, raw_results)]
    # Persist successful analyses so they survive a dashboard reload.
    for r in results:
        if not r.get("error"):
            await save_node_llm_analysis(
                r["node_id"], r["provider"], r.get("model", ""), r.get("premium", False),
                r.get("analysis") or {}, r.get("raw", ""),
            )
    return {"results": results, "budget": llm_providers.budget_status()}


@app.get("/api/compare/llm/{node_id}", tags=["LLM"])
async def get_saved_llm(node_id: str):
    """Previously-run LLM analyses for a node (populates the dropdown on expand)."""
    saved = await get_node_llm_analyses(node_id)
    for s in saved:
        s["label"] = llm_providers.LABELS.get(s.get("provider"), s.get("provider"))
    return {"node_id": node_id, "results": saved}


# ---------------------------------------------------------------------------
# Wazuh SIEM export (the feedback loop — integration claim, not detection)
# ---------------------------------------------------------------------------

class SigmaGenRequest(BaseModel):
    incident_id: Optional[str] = None   # L1 rule-engine incident
    node_id: Optional[str] = None       # L2 anomaly finding (rules missed it)
    provider: str = "gemini"
    premium: bool = False


@app.post("/api/wazuh/generate-sigma", tags=["Wazuh"])
async def generate_sigma(req: SigmaGenRequest):
    """LLM-author a Sigma rule from an L1 incident OR an L2 anomaly finding.

    The node_id path is the stronger feedback loop: it encodes knowledge the
    rules *missed* (an L2 flag) back into the SIEM as a signature. Returns the
    YAML for human review; the analyst pushes it via /api/wazuh/export-rule.
    Human-in-the-loop by design — integration claim, never autonomous response.
    """
    if req.provider not in llm_providers.PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider '{req.provider}'")

    if req.incident_id:
        incident = await get_incident(req.incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        context = llm_prompts.incident_to_context(incident.model_dump())
    elif req.node_id:
        sub = await get_node_subgraph(req.node_id, hops=1)
        if not sub["nodes"]:
            raise HTTPException(status_code=404, detail=f"Node not found: {req.node_id}")
        root = next((n for n in sub["nodes"] if n["id"] == req.node_id), {"id": req.node_id})
        node_meta = {"uuid": req.node_id, "label": root.get("label"), "name": root.get("name")}
        context = llm_prompts.subgraph_to_text(node_meta, sub)
    else:
        raise HTTPException(status_code=400, detail="Provide incident_id or node_id")
    res = await llm_providers.call_llm(
        req.provider, llm_prompts.SIGMA_SYSTEM, context,
        max_tokens=900, want_json=False, premium=req.premium,
    )
    if res["error"]:
        raise HTTPException(status_code=502, detail=f"LLM error: {res['error']}")
    sigma_yaml = llm_providers.strip_code_fence(res["raw"], lang="yaml")
    # Validate it parses as a Sigma-shaped mapping before handing it back.
    import yaml
    try:
        parsed = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=502, detail=f"LLM produced invalid YAML: {e}")
    if not isinstance(parsed, dict) or "detection" not in parsed:
        raise HTTPException(status_code=502, detail="LLM output is not a Sigma rule (no 'detection' block)")
    return {
        "provider": res["provider"], "model": res["model"], "premium": res["premium"],
        "sigma_yaml": sigma_yaml, "budget": llm_providers.budget_status(),
    }


class WazuhExportRequest(BaseModel):
    incident_id: Optional[str] = None
    sigma: Optional[str] = None  # raw Sigma YAML (LLM path); overrides incident


@app.post("/api/wazuh/export-rule", tags=["Wazuh"])
async def wazuh_export(req: WazuhExportRequest):
    """Convert a confirmed incident (or a supplied Sigma rule) to Wazuh XML, push
    it to the Wazuh manager via REST, and read it back to prove it arrived."""
    inc: dict = {}
    if req.incident_id:
        incident = await get_incident(req.incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        inc = incident.model_dump()
    elif not req.sigma:
        raise HTTPException(status_code=400, detail="Provide incident_id or sigma")
    try:
        return await export_incident_rule(inc, sigma_override=req.sigma)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh API error: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import uvicorn
    uvicorn.run("edr_server.main:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    main()
