"""FastAPI application — EDR API (Neo4j backend)."""

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
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
    title="EDR Server",
    description="Graph-based EDR API — reads from Neo4j provenance graph.",
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
# Entry point
# ---------------------------------------------------------------------------

def main():
    import uvicorn
    uvicorn.run("edr_server.main:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    main()
