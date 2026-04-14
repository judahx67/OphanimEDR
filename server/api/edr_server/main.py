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


@app.get("/api/graph/subgraph/{node_id}", tags=["Graph"])
async def node_subgraph(node_id: str, hops: int = Query(2, ge=1, le=4)):
    """K-hop neighbourhood of a provenance node (for graph explorer)."""
    result = await get_node_subgraph(node_id, hops=hops)
    if not result["nodes"]:
        raise HTTPException(status_code=404, detail="Node not found")
    return result


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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import uvicorn
    uvicorn.run("edr_server.main:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    main()
