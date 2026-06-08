"""One-shot backfill: populate matched_nodes/matched_edges/root_node_id on the
GNN->LLM incidents that were written before write_incident persisted the causal
subgraph. Roots each incident at its flagged seed node (event_id == node uuid)
and pulls the same 1-hop neighbourhood the live path now stores.

Run once inside the llm-analyzer container:
    docker exec server-llm-analyzer-1 python backfill_chains.py
"""

import json
import logging
import os

from neo4j import GraphDatabase

from subgraph import pull_subgraph, subgraph_to_matched

logging.basicConfig(level=logging.INFO, format="%(asctime)s [backfill] %(message)s")
log = logging.getLogger("backfill")

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "edr-thesis")

FIND = """
MATCH (i:Incident {source: 'ml-llm'})
WHERE i.matched_edges IS NULL OR i.matched_edges = '[]'
RETURN i.event_id AS eid
"""

SET = """
MATCH (i:Incident {event_id: $eid, source: 'ml-llm'})
SET i.matched_nodes = $matched_nodes,
    i.matched_edges = $matched_edges,
    i.root_node_id  = $eid
WITH i
OPTIONAL MATCH (root {uuid: $eid})
FOREACH (_ IN CASE WHEN root IS NULL THEN [] ELSE [1] END |
  MERGE (i)-[:TRIGGERED_BY {node_uuid: $eid}]->(root)
)
"""


def main() -> None:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        eids = [r["eid"] for r in session.run(FIND)]
    log.info("incidents to backfill: %d", len(eids))

    filled = empty = 0
    for eid in eids:
        # Seed node is both ends — pull_subgraph roots at the uuid neighbourhood.
        sg = pull_subgraph(driver, eid, eid, hops=1)
        nodes, edges = subgraph_to_matched(sg)
        with driver.session() as session:
            session.run(SET, eid=eid,
                        matched_nodes=json.dumps(nodes),
                        matched_edges=json.dumps(edges))
        if edges:
            filled += 1
        else:
            empty += 1
    log.info("done: %d with edges, %d still empty (no graph neighbourhood)", filled, empty)
    driver.close()


if __name__ == "__main__":
    main()
