"""
ML Engine — batch job.

Runs once: connects to Neo4j, extracts per-process graph features,
trains an XGBoost classifier using rule-engine Incident matched_nodes
as positive labels, writes ml_score back onto Process nodes, then exits.

Invoke via: docker compose --profile ml run --rm ml-engine
"""

import logging
import os
import sys
import time

from neo4j import GraphDatabase

from feature_extractor import extract
from trainer import train_and_score, writeback

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ml-engine] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ml-engine")

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "edr-thesis")


def _connect_neo4j():
    for attempt in range(1, 11):
        try:
            driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
            driver.verify_connectivity()
            log.info("Connected to Neo4j")
            return driver
        except Exception as exc:
            log.warning("Neo4j not ready (attempt %d/10): %s", attempt, exc)
            time.sleep(3)
    log.error("Could not connect to Neo4j")
    sys.exit(1)


def main():
    driver = _connect_neo4j()
    try:
        log.info("Extracting features from Neo4j")
        rows = extract(driver)
        if not rows:
            log.warning("No Process nodes found — nothing to do")
            return

        log.info("Training and scoring")
        scored = train_and_score(rows)

        log.info("Writing scores back to Neo4j")
        writeback(driver, scored)

        log.info("Done. %d processes scored.", len(scored))
    finally:
        driver.close()


if __name__ == "__main__":
    main()
