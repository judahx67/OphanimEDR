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
        # Neo4j 5 doesn't allow parameters as variable-length range bounds.
        # Cap at 2 hops max (1-hop is sufficient for edge neighbourhood).
        hops_clamped = min(int(hops), 2)
        hop_pattern = "-[*1..1]-" if hops_clamped == 1 else "-[*1..2]-"
        result = await session.run(
            f"""
            MATCH path = (root {{uuid: $uuid}}){hop_pattern}(neighbour)
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
              rel.timestamp AS timestamp,
              rel.size AS size,
              rel.properties AS properties,
              rel.botsv2_ml_score AS ml_score,
              rel.botsv2_ml_score_honest AS ml_score_honest,
              rel.botsv2_ml_alert AS ml_alert
            LIMIT 500
            """,
            {"uuid": node_id},
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
                props = {}
                if record["properties"]:
                    try:
                        import json as _json
                        props = _json.loads(record["properties"]) if isinstance(record["properties"], str) else dict(record["properties"])
                    except Exception:
                        pass
                edges.append({
                    "source": record["src_id"],
                    "target": record["dst_id"],
                    "type": record["edge_type"],
                    "event_id": record["event_id"],
                    "timestamp": record["timestamp"],
                    "size": int(record["size"]) if record["size"] is not None else None,
                    "properties": props,
                    "ml_score": float(record["ml_score"]) if record["ml_score"] is not None else None,
                    "ml_score_honest": float(record["ml_score_honest"]) if record["ml_score_honest"] is not None else None,
                    "ml_alert": record["ml_alert"],
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
    """
    Top-N Processes by ml_max_score (set by the ml-engine service).
    Each row carries the full per-tactic probability vector.
    """
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
                p.ml_top_tactic AS top_tactic,
                p.ml_tactic_scores AS tactic_scores,
                incident_count
            ORDER BY p.ml_score DESC
            LIMIT $limit
            """,
            limit=limit,
        )
        rows = []
        async for record in result:
            raw_scores = record["tactic_scores"]
            if isinstance(raw_scores, str):
                try:
                    import json
                    parsed_scores = json.loads(raw_scores)
                except Exception:
                    parsed_scores = {}
            else:
                parsed_scores = dict(raw_scores or {})
            rows.append({
                "uuid": record["uuid"],
                "name": record["name"],
                "score": float(record["score"]),
                "top_tactic": record["top_tactic"],
                "tactic_scores": parsed_scores,
                "incident_count": record["incident_count"],
            })
    return rows


async def get_ml_edge_findings(
    rule_clear: bool = True,
    limit: int = 50,
    min_score: float = 0.0,
) -> list[dict]:
    """
    Top-scoring BOTSv2 edges from the ml-edge-scorer.

    rule_clear=True filters to edges with no linked rule-engine Incident
    — these are the "ML found what rules missed" headline thesis query.
    """
    driver = get_driver()

    # Two variants: rule-clear (no incident on subject/object nodes) vs all scored.
    # BOTSv2 incidents are tracked by matched_nodes UUIDs; the min_score parameter
    # provides the score-band filter for the "ML caught what rules missed" headline.
    rule_filter = """
          AND NOT exists {
            MATCH (i:Incident)
            WHERE s.uuid IN i.matched_nodes OR o.uuid IN i.matched_nodes
          }
    """ if rule_clear else ""

    # Deduplicate by (subject, object, edge_type) and stratify by edge_type so
    # one high-volume sourcetype (e.g. stream:http gacrux→brewertalk) cannot
    # crowd out lower-volume but still interesting types (CONNECT/FORK/etc.).
    # Per-type cap = ceil(limit / 4) ensures at least 4 edge types get airtime
    # when present; remaining slots backfill by global score.
    cypher = f"""
    MATCH (s)-[r]->(o)
    WHERE r.botsv2_ml_score IS NOT NULL
      AND r.botsv2_ml_score_honest >= $min_score
      AND r.botsv2_ml_score_quality = 'full'
    {rule_filter}
    WITH s, o, type(r) AS edge_type,
         max(r.botsv2_ml_score_honest) AS best_honest
    MATCH (s)-[r2]->(o)
    WHERE type(r2) = edge_type
      AND r2.botsv2_ml_score_honest = best_honest
    WITH r2, s, o, edge_type, best_honest
    ORDER BY best_honest DESC
    WITH edge_type, collect({{
        event_id: r2.event_id,
        score_headline: r2.botsv2_ml_score,
        score_honest: r2.botsv2_ml_score_honest,
        quality: r2.botsv2_ml_score_quality,
        is_alert: r2.botsv2_ml_alert,
        timestamp: r2.timestamp,
        subj_id: s.uuid, subj_name: s.name, subj_label: labels(s)[0],
        obj_id: o.uuid,  obj_name: o.name,  obj_label: labels(o)[0],
        endpoint_id: r2.endpoint_id,
        best_honest: best_honest
    }}) AS rows_for_type
    // Cap each edge type at half the global limit. Prevents one high-volume
    // type from monopolising the page while still permitting bursts when
    // only one type is active.
    WITH edge_type, rows_for_type[0..toInteger(($limit + 1) / 2)] AS top_per_type
    UNWIND top_per_type AS row
    WITH row, edge_type, row.best_honest AS h
    ORDER BY h DESC
    RETURN
        row.event_id        AS event_id,
        edge_type           AS edge_type,
        row.score_headline  AS score_headline,
        row.score_honest    AS score_honest,
        row.quality         AS quality,
        row.is_alert        AS is_alert,
        row.timestamp       AS timestamp,
        row.subj_id AS subj_id, row.subj_name AS subj_name, row.subj_label AS subj_label,
        row.obj_id  AS obj_id,  row.obj_name  AS obj_name,  row.obj_label  AS obj_label,
        row.endpoint_id     AS endpoint_id
    LIMIT $limit
    """

    async with driver.session() as session:
        result = await session.run(cypher, limit=limit, min_score=min_score)
        rows = []
        async for rec in result:
            score_h = rec["score_headline"]
            score_o = rec["score_honest"]
            rows.append({
                "event_id": rec["event_id"],
                "edge_type": rec["edge_type"],
                "score_headline": float(score_h) if score_h is not None else None,
                "score_honest": float(score_o) if score_o is not None else None,
                "quality": rec["quality"],
                "is_alert": rec["is_alert"],
                "timestamp": rec["timestamp"],
                "subject": {
                    "id": rec["subj_id"], "name": rec["subj_name"], "label": rec["subj_label"],
                },
                "object": {
                    "id": rec["obj_id"], "name": rec["obj_name"], "label": rec["obj_label"],
                },
                "endpoint_id": rec["endpoint_id"],
            })
    return rows


async def get_ml_edge_by_event_id(event_id: str) -> dict | None:
    """
    Fetch a single ML-scored edge by its exact event_id, bypassing the
    (subject, object, edge_type) dedup applied by `get_ml_edge_findings`.
    Used by the UI when filtering by a specific event_id that may have
    been collapsed under a sibling representative in the top-N query.
    """
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (s)-[r {event_id: $event_id}]->(o)
            WHERE r.botsv2_ml_score IS NOT NULL
            RETURN
                r.event_id        AS event_id,
                type(r)           AS edge_type,
                r.botsv2_ml_score         AS score_headline,
                r.botsv2_ml_score_honest  AS score_honest,
                r.botsv2_ml_score_quality AS quality,
                r.botsv2_ml_alert         AS is_alert,
                r.timestamp               AS timestamp,
                s.uuid AS subj_id, s.name AS subj_name, labels(s)[0] AS subj_label,
                o.uuid AS obj_id,  o.name AS obj_name,  labels(o)[0] AS obj_label,
                r.endpoint_id AS endpoint_id
            LIMIT 1
            """,
            event_id=event_id,
        )
        rec = await result.single()
        if not rec:
            return None
        score_h = rec["score_headline"]
        score_o = rec["score_honest"]
        return {
            "event_id": rec["event_id"],
            "edge_type": rec["edge_type"],
            "score_headline": float(score_h) if score_h is not None else None,
            "score_honest": float(score_o) if score_o is not None else None,
            "quality": rec["quality"],
            "is_alert": rec["is_alert"],
            "timestamp": rec["timestamp"],
            "subject": {
                "id": rec["subj_id"], "name": rec["subj_name"], "label": rec["subj_label"],
            },
            "object": {
                "id": rec["obj_id"], "name": rec["obj_name"], "label": rec["obj_label"],
            },
            "endpoint_id": rec["endpoint_id"],
        }


async def get_ml_edge_summary() -> dict:
    """Stats on botsv2_ml_score distribution across all scored edges."""
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH ()-[r]->()
            WHERE r.botsv2_ml_score IS NOT NULL
            WITH
                count(r) AS total,
                avg(r.botsv2_ml_score) AS mean_headline,
                avg(r.botsv2_ml_score_honest) AS mean_honest,
                size([x IN collect(r.botsv2_ml_score) WHERE x >= 0.9]) AS alerts_headline,
                size([x IN collect(r.botsv2_ml_score_honest) WHERE x >= 0.7]) AS alerts_honest,
                size([x IN collect(r.botsv2_ml_score_quality) WHERE x = 'degraded']) AS degraded
            RETURN total, mean_headline, mean_honest,
                   alerts_headline, alerts_honest, degraded
            """
        )
        rec = await result.single()
        if not rec or rec["total"] == 0:
            return {
                "total_scored": 0,
                "mean_headline": 0.0,
                "mean_honest": 0.0,
                "alerts_headline": 0,
                "alerts_honest": 0,
                "degraded": 0,
            }
        return {
            "total_scored": rec["total"],
            "mean_headline": float(rec["mean_headline"] or 0),
            "mean_honest": float(rec["mean_honest"] or 0),
            "alerts_headline": rec["alerts_headline"],
            "alerts_honest": rec["alerts_honest"],
            "degraded": rec["degraded"],
        }


async def get_llm_incident(event_id: str) -> dict | None:
    """Fetch the LLM-generated narrative for a given edge event_id."""
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (i:Incident {event_id: $event_id, source: 'ml-llm'})
            RETURN
                i.title AS title,
                i.attack_hypothesis AS attack_hypothesis,
                i.mitre_technique AS mitre_technique,
                i.mitre_tactic AS mitre_tactic,
                i.evidence_summary AS evidence_summary,
                i.confidence AS confidence,
                i.analyst_action AS analyst_action,
                i.false_positive_risk AS false_positive_risk,
                i.score_headline AS score_headline,
                i.score_honest AS score_honest,
                i.severity AS severity,
                i.created_at AS created_at,
                i.endpoint_id AS endpoint_id
            """,
            event_id=event_id,
        )
        rec = await result.single()
        if not rec:
            return None
        return dict(rec)


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
