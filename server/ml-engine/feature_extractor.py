"""
Feature extraction for per-Process classification.

Queries Neo4j for every Process node and computes ~12 graph-topology
features. All counts are derived from outgoing/incoming edges in the
provenance graph built by the graph-builder service.

Output: list[dict] with keys:
    uuid, name, features (dict of floats), label (0 or 1)
"""

import logging

log = logging.getLogger("ml-engine.features")


FEATURE_QUERY = """
MATCH (p:Process)
OPTIONAL MATCH (p)-[out]->()
WITH p, collect(out) AS outs
OPTIONAL MATCH ()-[in_]->(p)
WITH p, outs, collect(in_) AS ins
RETURN
    p.uuid AS uuid,
    coalesce(p.name, '') AS name,
    size(outs) AS out_degree,
    size(ins) AS in_degree,
    size([e IN outs WHERE type(e) = 'WRITE']) AS file_write_count,
    size([e IN outs WHERE type(e) = 'READ']) AS file_read_count,
    size([e IN outs WHERE type(e) = 'DELETE']) AS file_delete_count,
    size([e IN outs WHERE type(e) = 'CONNECT']) AS socket_connect_count,
    size([e IN outs WHERE type(e) = 'SEND']) AS socket_send_count,
    size([e IN outs WHERE type(e) = 'RECEIVE']) AS socket_recv_count,
    size([e IN outs WHERE type(e) = 'FORK']) AS child_process_count,
    size([e IN outs WHERE type(e) = 'EXEC']) AS exec_count,
    size([e IN outs WHERE type(e) = 'MMAP']) AS mmap_count,
    size([e IN outs WHERE type(e) = 'LOAD']) AS load_count,
    size(apoc.coll.toSet([e IN outs | type(e)])) AS edge_type_distinct_count
"""

# Fallback if APOC not installed
FEATURE_QUERY_NO_APOC = """
MATCH (p:Process)
OPTIONAL MATCH (p)-[out]->()
WITH p, collect(out) AS outs
OPTIONAL MATCH ()-[in_]->(p)
WITH p, outs, collect(in_) AS ins
RETURN
    p.uuid AS uuid,
    coalesce(p.name, '') AS name,
    size(outs) AS out_degree,
    size(ins) AS in_degree,
    size([e IN outs WHERE type(e) = 'WRITE']) AS file_write_count,
    size([e IN outs WHERE type(e) = 'READ']) AS file_read_count,
    size([e IN outs WHERE type(e) = 'DELETE']) AS file_delete_count,
    size([e IN outs WHERE type(e) = 'CONNECT']) AS socket_connect_count,
    size([e IN outs WHERE type(e) = 'SEND']) AS socket_send_count,
    size([e IN outs WHERE type(e) = 'RECEIVE']) AS socket_recv_count,
    size([e IN outs WHERE type(e) = 'FORK']) AS child_process_count,
    size([e IN outs WHERE type(e) = 'EXEC']) AS exec_count,
    size([e IN outs WHERE type(e) = 'MMAP']) AS mmap_count,
    size([e IN outs WHERE type(e) = 'LOAD']) AS load_count
"""


LABEL_QUERY = """
MATCH (i:Incident)
UNWIND i.matched_nodes AS node_id
RETURN collect(DISTINCT node_id) AS positive_uuids
"""


FEATURE_NAMES = [
    "out_degree",
    "in_degree",
    "file_write_count",
    "file_read_count",
    "file_delete_count",
    "socket_connect_count",
    "socket_send_count",
    "socket_recv_count",
    "child_process_count",
    "exec_count",
    "mmap_count",
    "load_count",
]


def extract(driver) -> list[dict]:
    """Query Neo4j and return per-process feature rows with labels."""
    with driver.session() as s:
        result = s.run(FEATURE_QUERY_NO_APOC)
        rows = [dict(r) for r in result]
        label_result = s.run(LABEL_QUERY).single()
        positive_uuids = set(label_result["positive_uuids"]) if label_result else set()

    for r in rows:
        r["label"] = 1 if r["uuid"] in positive_uuids else 0
        r["features"] = {k: float(r.get(k, 0) or 0) for k in FEATURE_NAMES}

    n_pos = sum(1 for r in rows if r["label"] == 1)
    log.info(
        "Extracted %d processes, %d positive labels from incidents",
        len(rows),
        n_pos,
    )
    return rows
