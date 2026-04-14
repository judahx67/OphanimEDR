"""Neo4j database connection and query operations for the EDR API."""

import os
from datetime import datetime, timezone
from typing import Optional

from neo4j import AsyncGraphDatabase, AsyncDriver

from .models import (
    GraphStats,
    IncidentInDB,
    IncidentStatus,
    IncidentSeverity,
)


_driver: Optional[AsyncDriver] = None


def _neo4j_uri() -> str:
    return os.environ.get("NEO4J_URI", "bolt://localhost:7687")


def _neo4j_auth() -> tuple[str, str]:
    return (
        os.environ.get("NEO4J_USER", "neo4j"),
        os.environ.get("NEO4J_PASS", "edr-thesis"),
    )


async def connect_db() -> None:
    global _driver
    _driver = AsyncGraphDatabase.driver(_neo4j_uri(), auth=_neo4j_auth())
    # Verify connectivity
    await _driver.verify_connectivity()
    # Ensure incident constraint exists
    async with _driver.session() as session:
        await session.run(
            "CREATE CONSTRAINT incident_id IF NOT EXISTS "
            "FOR (i:Incident) REQUIRE i.incident_id IS UNIQUE"
        )
    print(f"Connected to Neo4j: {_neo4j_uri()}")


async def close_db() -> None:
    global _driver
    if _driver:
        await _driver.close()
        print("Neo4j connection closed")


def get_driver() -> AsyncDriver:
    if _driver is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _driver


# ---------------------------------------------------------------------------
# Graph stats
# ---------------------------------------------------------------------------

async def get_graph_stats() -> GraphStats:
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run("""
            MATCH (n)
            RETURN labels(n)[0] AS label, count(n) AS cnt
        """)
        node_counts: dict[str, int] = {}
        async for record in result:
            lbl = record["label"]
            if lbl:
                node_counts[lbl] = record["cnt"]

        edge_result = await session.run("MATCH ()-[r]->() RETURN count(r) AS cnt")
        edge_record = await edge_result.single()
        total_edges = edge_record["cnt"] if edge_record else 0

        incident_result = await session.run(
            "MATCH (i:Incident) RETURN count(i) AS cnt"
        )
        inc_record = await incident_result.single()
        total_incidents = inc_record["cnt"] if inc_record else 0

        new_result = await session.run(
            "MATCH (i:Incident {status: 'new'}) RETURN count(i) AS cnt"
        )
        new_record = await new_result.single()
        new_incidents = new_record["cnt"] if new_record else 0

    return GraphStats(
        node_counts=node_counts,
        total_edges=total_edges,
        total_incidents=total_incidents,
        new_incidents=new_incidents,
        process_count=node_counts.get("Process", 0),
        file_count=node_counts.get("File", 0),
        socket_count=node_counts.get("Socket", 0),
    )


# ---------------------------------------------------------------------------
# Incident operations
# ---------------------------------------------------------------------------

def _record_to_incident(record: dict) -> IncidentInDB:
    i = record["i"]
    props = dict(i)
    # Convert neo4j DateTime / ISO string -> python datetime
    for field in ("created_at", "updated_at"):
        val = props.get(field)
        if val is None or isinstance(val, datetime):
            pass
        elif isinstance(val, str):
            props[field] = datetime.fromisoformat(val)
        else:
            # neo4j DateTime object
            props[field] = val.to_native()
    # matched_nodes / matched_edges are stored as JSON strings
    import json
    for field in ("matched_nodes", "matched_edges", "rule_conditions"):
        val = props.get(field)
        if isinstance(val, str):
            try:
                props[field] = json.loads(val)
            except Exception:
                props[field] = []
    return IncidentInDB(**props)


async def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
) -> tuple[list[IncidentInDB], int]:
    driver = get_driver()
    async with driver.session() as session:
        where_clauses = []
        params: dict = {"limit": limit, "skip": skip}

        if status:
            where_clauses.append("i.status = $status")
            params["status"] = status
        if severity:
            where_clauses.append("i.severity = $severity")
            params["severity"] = severity
        if rule_id:
            where_clauses.append("i.rule_id = $rule_id")
            params["rule_id"] = rule_id
        if search:
            where_clauses.append(
                "(toLower(i.title) CONTAINS toLower($search) OR "
                "toLower(i.description) CONTAINS toLower($search))"
            )
            params["search"] = search

        where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        count_result = await session.run(
            f"MATCH (i:Incident) {where} RETURN count(i) AS cnt", params
        )
        count_record = await count_result.single()
        total = count_record["cnt"] if count_record else 0

        result = await session.run(
            f"""
            MATCH (i:Incident)
            {where}
            RETURN i
            ORDER BY i.created_at DESC
            SKIP $skip LIMIT $limit
            """,
            params,
        )
        incidents = []
        async for record in result:
            incidents.append(_record_to_incident(dict(record)))

    return incidents, total


async def get_incident(incident_id: str) -> Optional[IncidentInDB]:
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(
            "MATCH (i:Incident {incident_id: $id}) RETURN i",
            {"id": incident_id},
        )
        record = await result.single()
        if record:
            return _record_to_incident(dict(record))
    return None


async def update_incident_status(
    incident_id: str, new_status: IncidentStatus, notes: str = ""
) -> bool:
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (i:Incident {incident_id: $id})
            SET i.status = $status,
                i.updated_at = $updated_at,
                i.notes = CASE WHEN $notes <> '' THEN $notes ELSE i.notes END
            RETURN i
            """,
            {
                "id": incident_id,
                "status": new_status.value,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "notes": notes,
            },
        )
        record = await result.single()
        return record is not None


async def get_incident_stats() -> dict:
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run("""
            MATCH (i:Incident)
            RETURN
              count(i) AS total,
              sum(CASE WHEN i.status = 'new' THEN 1 ELSE 0 END) AS new,
              sum(CASE WHEN i.status = 'investigating' THEN 1 ELSE 0 END) AS investigating,
              sum(CASE WHEN i.status = 'resolved' THEN 1 ELSE 0 END) AS resolved,
              sum(CASE WHEN i.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
              sum(CASE WHEN i.severity = 'high' THEN 1 ELSE 0 END) AS high,
              sum(CASE WHEN i.severity = 'medium' THEN 1 ELSE 0 END) AS medium,
              sum(CASE WHEN i.severity = 'low' THEN 1 ELSE 0 END) AS low
        """)
        record = await result.single()
        if not record:
            return {"total": 0, "new": 0, "investigating": 0, "resolved": 0,
                    "by_severity": {}}
        return {
            "total": record["total"],
            "new": record["new"],
            "investigating": record["investigating"],
            "resolved": record["resolved"],
            "by_severity": {
                "critical": record["critical"],
                "high": record["high"],
                "medium": record["medium"],
                "low": record["low"],
            },
        }


# ---------------------------------------------------------------------------
# Endpoint summary — derived from provenance graph
# ---------------------------------------------------------------------------

async def get_graph_endpoints() -> list[dict]:
    """Return one row per distinct endpoint_id seen in the provenance graph."""
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run("""
            MATCH (p:Process)
            WHERE p.endpoint_id IS NOT NULL
            WITH p.endpoint_id AS eid
            CALL {
                WITH eid
                MATCH (n {endpoint_id: eid})
                RETURN count(n) AS node_count
            }
            CALL {
                WITH eid
                MATCH (s {endpoint_id: eid})-[r]->()
                RETURN count(r) AS edge_count
            }
            CALL {
                WITH eid
                MATCH (i:Incident {endpoint_id: eid})
                RETURN count(i) AS incident_count,
                       sum(CASE WHEN i.status = 'new' THEN 1 ELSE 0 END) AS new_incidents
            }
            CALL {
                WITH eid
                MATCH (p2:Process {endpoint_id: eid})
                RETURN max(p2.last_seen) AS last_seen
            }
            RETURN eid, node_count, edge_count, incident_count, new_incidents, last_seen
            ORDER BY incident_count DESC, edge_count DESC
        """)
        endpoints = []
        async for record in result:
            endpoints.append({
                "endpoint_id": record["eid"],
                "node_count": record["node_count"],
                "edge_count": record["edge_count"],
                "incident_count": record["incident_count"],
                "new_incidents": record["new_incidents"],
                "last_seen": record["last_seen"],
            })
    return endpoints


# ---------------------------------------------------------------------------
# Provenance graph queries (for graph explorer)
# ---------------------------------------------------------------------------

async def get_node_subgraph(node_id: str, hops: int = 2) -> dict:
    """Return the k-hop neighbourhood of a node as nodes + edges."""
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH path = (root {uuid: $uuid})-[*1..$hops]-(neighbour)
            UNWIND relationships(path) AS rel
            WITH
              startNode(rel) AS src,
              endNode(rel)   AS dst,
              rel
            RETURN DISTINCT
              src.uuid AS src_id, labels(src)[0] AS src_label, src.name AS src_name,
              dst.uuid AS dst_id, labels(dst)[0] AS dst_label, dst.name AS dst_name,
              type(rel) AS edge_type,
              rel.event_id AS event_id,
              rel.timestamp AS timestamp
            LIMIT 500
            """,
            {"uuid": node_id, "hops": hops},
        )
        nodes: dict[str, dict] = {}
        edges: list[dict] = []
        async for record in result:
            for uid, label, name in [
                (record["src_id"], record["src_label"], record["src_name"]),
                (record["dst_id"], record["dst_label"], record["dst_name"]),
            ]:
                if uid and uid not in nodes:
                    nodes[uid] = {"id": uid, "label": label, "name": name or uid}
            if record["src_id"] and record["dst_id"]:
                edges.append({
                    "source": record["src_id"],
                    "target": record["dst_id"],
                    "type": record["edge_type"],
                    "event_id": record["event_id"],
                    "timestamp": record["timestamp"],
                })
    return {"nodes": list(nodes.values()), "edges": edges}


async def get_recent_edges(limit: int = 100) -> list[dict]:
    """Return the most recent edges in the graph."""
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (s)-[r]->(o)
            WHERE r.timestamp IS NOT NULL
            RETURN
              s.uuid AS src_id, labels(s)[0] AS src_label, s.name AS src_name,
              o.uuid AS dst_id, labels(o)[0] AS dst_label, o.name AS dst_name,
              type(r) AS edge_type,
              r.event_id AS event_id,
              r.timestamp AS ts
            ORDER BY r.timestamp DESC
            LIMIT $limit
            """,
            {"limit": limit},
        )
        edges = []
        async for record in result:
            edges.append({
                "src_id": record["src_id"],
                "src_label": record["src_label"],
                "src_name": record["src_name"],
                "dst_id": record["dst_id"],
                "dst_label": record["dst_label"],
                "dst_name": record["dst_name"],
                "edge_type": record["edge_type"],
                "event_id": record["event_id"],
                "timestamp": record["ts"],
            })
    return edges


# ---------------------------------------------------------------------------
# ML scores (written by ml-engine batch job)
# ---------------------------------------------------------------------------

async def get_ml_scores(limit: int = 100) -> list[dict]:
    """Top-N Processes by ml_score (set by the ml-engine service)."""
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (p:Process)
            WHERE p.ml_score IS NOT NULL
            OPTIONAL MATCH (i:Incident) WHERE p.uuid IN i.matched_nodes
            WITH p, count(DISTINCT i) AS incident_count
            RETURN
                p.uuid AS uuid,
                coalesce(p.name, '') AS name,
                p.ml_score AS score,
                incident_count
            ORDER BY p.ml_score DESC
            LIMIT $limit
            """,
            limit=limit,
        )
        rows = []
        async for record in result:
            rows.append({
                "uuid": record["uuid"],
                "name": record["name"],
                "score": float(record["score"]),
                "incident_count": record["incident_count"],
            })
    return rows


async def get_ml_summary() -> dict:
    """Aggregate stats on ml_score distribution."""
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (p:Process)
            WHERE p.ml_score IS NOT NULL
            RETURN
                count(p) AS scored,
                avg(p.ml_score) AS mean,
                max(p.ml_score) AS max,
                size([x IN collect(p.ml_score) WHERE x >= 0.5]) AS high
            """
        )
        record = await result.single()
        if not record or record["scored"] == 0:
            return {"scored": 0, "mean": 0.0, "max": 0.0, "high": 0}
        return {
            "scored": record["scored"],
            "mean": float(record["mean"] or 0),
            "max": float(record["max"] or 0),
            "high": record["high"],
        }
