#!/usr/bin/env python3
"""
EDR -- End-to-end experiment runner.

Automates the full DARPA THEIA E3 provenance pipeline experiment:
  1. Verify infrastructure (docker services)
  2. Clean previous state (Neo4j, RabbitMQ queues)
  3. Rebuild & restart workers (ingest, graph-builder)
  4. Replay DARPA THEIA E3 data via the simulator
  5. Wait for the pipeline to drain
  6. Query Neo4j for results
  7. Print a formatted experiment report

Usage:
  cd j:/THESIS-EDR/server
  python run_experiment.py                          # defaults: 30k events, rate 5000
  python run_experiment.py --limit 50000 --rate 2000
  python run_experiment.py --skip-events 20000      # jump past boot storm

The script expects `docker compose` services to be defined in docker-compose.yml
in the current directory.
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone


# --Helpers ---------------------------------------------------------------

def run(cmd: str, capture=True, timeout=300) -> str:
    """Run a shell command, return stdout. Raises on failure."""
    result = subprocess.run(
        cmd, shell=True, capture_output=capture,
        text=True, timeout=timeout,
    )
    if result.returncode != 0 and capture:
        print(f"  [ERROR] {cmd}")
        print(f"  stderr: {result.stderr.strip()}")
    return result.stdout.strip() if capture else ""


def cypher(query: str) -> str:
    """Execute a Cypher query against the local Neo4j."""
    return run(
        f'docker exec edr-neo4j cypher-shell -u neo4j -p edr-thesis "{query}"'
    )


def header(text: str):
    width = 72
    print()
    print("=" * width)
    print(f"  {text}")
    print("=" * width)


def step(n: int, text: str):
    print(f"\n-- Step {n}: {text} {'-' * max(1, 52 - len(text))}")


# --Experiment steps ------------------------------------------------------

def verify_services() -> dict:
    """Check that rabbitmq and neo4j are healthy."""
    ps_output = run("docker compose ps --format json")
    services = {}
    for line in ps_output.splitlines():
        try:
            svc = json.loads(line)
            services[svc.get("Service", svc.get("service", ""))] = svc
        except json.JSONDecodeError:
            continue
    return services


def clean_state():
    """Wipe Neo4j graph and purge RabbitMQ queues."""
    cypher("MATCH (n) DETACH DELETE n")
    run("docker exec edr-rabbitmq rabbitmqctl purge_queue raw_events")
    run("docker exec edr-rabbitmq rabbitmqctl purge_queue normalized_events")


def rebuild_workers():
    """Rebuild and force-recreate ingest + graph-builder."""
    run("docker compose build ingest graph-builder simulator", timeout=600)
    run("docker compose up -d --force-recreate ingest graph-builder")


def run_simulator(limit: int, rate: int, skip_events: int) -> dict:
    """Run the THEIA simulator and parse its final stats."""
    cmd = (
        f"docker compose run --rm simulator "
        f"--scenario theia --limit {limit} --rate {rate} "
        f"--skip-events {skip_events}"
    )
    t0 = time.time()
    output = run(cmd, timeout=600)
    elapsed = time.time() - t0

    # Parse the final stats from the simulator output
    stats = {"elapsed_s": round(elapsed, 1), "raw_output": ""}
    for line in output.splitlines():
        if "THEIA loader done" in line:
            stats["raw_output"] = line.split("INFO: ", 1)[-1] if "INFO:" in line else line
        if "Datum type breakdown" in line:
            stats["breakdown"] = line.split("INFO: ", 1)[-1] if "INFO:" in line else line
    return stats


def wait_for_drain(timeout=120) -> float:
    """Wait until both RabbitMQ queues reach 0 messages."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        output = run("docker exec edr-rabbitmq rabbitmqctl list_queues")
        total = 0
        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                total += int(parts[1])
        if total == 0:
            return round(time.time() - t0, 1)
        time.sleep(2)
    return round(time.time() - t0, 1)


def query_graph_summary() -> dict:
    """Query Neo4j for node/edge counts and sample data."""
    summary = {}

    # Node counts by label
    raw = cypher("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS c ORDER BY c DESC")
    nodes = {}
    for line in raw.splitlines():
        if line.startswith('"'):
            parts = line.split(", ")
            if len(parts) == 2:
                label = parts[0].strip('"')
                count = int(parts[1])
                nodes[label] = count
    summary["nodes"] = nodes
    summary["total_nodes"] = sum(nodes.values())

    # Edge counts by type
    raw = cypher("MATCH ()-[r]->() RETURN type(r) AS edge, count(*) AS c ORDER BY c DESC")
    edges = {}
    for line in raw.splitlines():
        if line.startswith('"'):
            parts = line.split(", ")
            if len(parts) == 2:
                etype = parts[0].strip('"')
                count = int(parts[1])
                edges[etype] = count
    summary["edges"] = edges
    summary["total_edges"] = sum(edges.values())

    # Sample processes
    raw = cypher(
        "MATCH (p:Process) WHERE NOT p.name STARTS WITH 'process:' "
        "AND NOT p.name = 'swapper/0' "
        "RETURN DISTINCT p.name AS name LIMIT 15"
    )
    summary["sample_processes"] = [
        l.strip('"') for l in raw.splitlines() if l.startswith('"')
    ]

    # Fork tree sample
    raw = cypher(
        "MATCH (parent:Process)-[:FORK]->(child:Process) "
        "RETURN DISTINCT parent.name AS p, child.name AS c LIMIT 10"
    )
    forks = []
    for line in raw.splitlines():
        if line.startswith('"'):
            parts = line.split('", "')
            if len(parts) == 2:
                forks.append((parts[0].strip('"'), parts[1].strip('"')))
    summary["sample_forks"] = forks

    # Network connections
    raw = cypher(
        "MATCH (p:Process)-[:CONNECT]->(s:Socket) "
        "WHERE NOT s.name STARTS WITH 'socket:' "
        "RETURN DISTINCT p.name AS proc, s.name AS remote LIMIT 10"
    )
    conns = []
    for line in raw.splitlines():
        if line.startswith('"'):
            parts = line.split('", "')
            if len(parts) == 2:
                conns.append((parts[0].strip('"'), parts[1].strip('"')))
    summary["network_connections"] = conns

    # Sensitive file writes
    raw = cypher(
        "MATCH (p:Process)-[:WRITE]->(f:File) "
        "WHERE f.name =~ '.*(log|history|utmp|wtmp|\\\\\\\\.ssh|cron|passwd|shadow).*' "
        "RETURN DISTINCT p.name AS proc, f.name AS file LIMIT 10"
    )
    writes = []
    for line in raw.splitlines():
        if line.startswith('"'):
            parts = line.split('", "')
            if len(parts) == 2:
                writes.append((parts[0].strip('"'), parts[1].strip('"')))
    summary["sensitive_writes"] = writes

    # Busiest processes (top 5 by out-degree)
    raw = cypher(
        "MATCH (p:Process)-[r]->() "
        "RETURN p.name AS process, count(r) AS degree "
        "ORDER BY degree DESC LIMIT 5"
    )
    busy = []
    for line in raw.splitlines():
        if line.startswith('"'):
            parts = line.rsplit(", ", 1)
            if len(parts) == 2:
                busy.append((parts[0].strip('"'), int(parts[1])))
    summary["busiest_processes"] = busy

    # Causal chain example (fork -> connect)
    raw = cypher(
        "MATCH (parent:Process)-[:FORK]->(child:Process)-[:CONNECT]->(s:Socket) "
        "WHERE NOT s.name STARTS WITH 'socket:' "
        "RETURN DISTINCT parent.name, child.name, s.name LIMIT 5"
    )
    chains = []
    for line in raw.splitlines():
        if line.startswith('"'):
            parts = line.split('", "')
            if len(parts) == 3:
                chains.append((
                    parts[0].strip('"'),
                    parts[1].strip('"'),
                    parts[2].strip('"'),
                ))
    summary["fork_to_connect"] = chains

    return summary


# --Report ----------------------------------------------------------------

def print_report(args, sim_stats: dict, drain_time: float, summary: dict):
    """Print the final experiment report."""
    header("OPHANIM-EDR EXPERIMENT REPORT")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"  Timestamp   : {now}")
    print(f"  Dataset     : DARPA THEIA E3 (ta1-theia-e3-official-1r.json.0)")
    print(f"  Event limit : {args.limit:,}")
    print(f"  Skip events : {args.skip_events:,}")
    print(f"  Rate        : {args.rate:,}/s")

    # --Pipeline timing
    header("PIPELINE TIMING")
    print(f"  Simulator      : {sim_stats.get('elapsed_s', '?')}s")
    print(f"  Queue drain    : {drain_time}s")
    if sim_stats.get("raw_output"):
        print(f"  Simulator log  : {sim_stats['raw_output']}")

    # --Graph summary
    header("PROVENANCE GRAPH SUMMARY")
    print(f"  Total nodes    : {summary['total_nodes']:,}")
    print(f"  Total edges    : {summary['total_edges']:,}")
    print()
    print("  Node counts by label:")
    for label, count in summary["nodes"].items():
        bar = "#" * min(count // 20, 40)
        print(f"    {label:<12} {count:>6,}  {bar}")
    print()
    print("  Edge counts by type:")
    for etype, count in summary["edges"].items():
        bar = "#" * min(count // 50, 40)
        print(f"    {etype:<12} {count:>6,}  {bar}")

    # --Process tree
    if summary.get("sample_forks"):
        header("PROCESS TREE (sample FORK edges)")
        for parent, child in summary["sample_forks"]:
            print(f"    {parent}")
            print(f"      `-> {child}")

    # --Network activity
    if summary.get("network_connections"):
        header("NETWORK ACTIVITY (CONNECT edges)")
        for proc, remote in summary["network_connections"]:
            print(f"    {proc}  -->  {remote}")

    # --Sensitive writes
    if summary.get("sensitive_writes"):
        header("SENSITIVE FILE WRITES")
        for proc, fname in summary["sensitive_writes"]:
            print(f"    {proc}  -->  {fname}")

    # --Fork -> Connect chains
    if summary.get("fork_to_connect"):
        header("CAUSAL CHAINS: FORK -> CONNECT (EDR detection pattern)")
        for parent, child, socket in summary["fork_to_connect"]:
            print(f"    {parent}")
            print(f"      `-FORK-> {child}")
            print(f"                 `-CONNECT-> {socket}")

    # --Busiest processes
    if summary.get("busiest_processes"):
        header("BUSIEST PROCESSES (by out-degree)")
        for proc, degree in summary["busiest_processes"]:
            bar = "#" * min(degree // 100, 40)
            print(f"    {degree:>6,}  {proc[:60]}  {bar}")

    # --Sample processes
    if summary.get("sample_processes"):
        header("SAMPLE PROCESS NAMES (from real THEIA data)")
        for name in summary["sample_processes"]:
            print(f"    - {name}")

    # --Footer
    print()
    print("=" * 72)
    print("  Neo4j Browser : http://localhost:7474  (neo4j / edr-thesis)")
    print("  RabbitMQ UI   : http://localhost:15672 (guest / guest)")
    print("  Demo queries  : server/neo4j-demo-queries.cypher")
    print("=" * 72)
    print()


# --Main ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Run the EDR THEIA E3 experiment end-to-end",
    )
    parser.add_argument("--limit", type=int, default=30000,
                        help="Number of Event datums to replay (default: 30000)")
    parser.add_argument("--rate", type=int, default=5000,
                        help="Simulator publish rate in datums/sec (default: 5000)")
    parser.add_argument("--skip-events", type=int, default=0,
                        help="Skip past the first N Event datums")
    parser.add_argument("--no-rebuild", action="store_true",
                        help="Skip the docker build step")
    parser.add_argument("--no-clean", action="store_true",
                        help="Skip the Neo4j wipe + queue purge (append to existing graph)")
    args = parser.parse_args()

    header("OPHANIM-EDR EXPERIMENT RUNNER")
    print(f"  Config: limit={args.limit:,}  rate={args.rate}/s  skip={args.skip_events:,}")

    # Step 1: verify
    step(1, "Verify infrastructure")
    services = verify_services()
    required = {"rabbitmq", "neo4j", "ingest", "graph-builder"}
    running = set(services.keys()) & required
    missing = required - running
    if missing:
        print(f"  [WARN] Missing services: {missing}")
        print("  Starting services...")
        run("docker compose up -d", timeout=120)
        print("  Waiting 15s for services to become healthy...")
        time.sleep(15)
    else:
        print(f"  OK All {len(required)} services running")

    # Step 2: clean
    if not args.no_clean:
        step(2, "Clean previous state")
        clean_state()
        print("  OK Neo4j wiped, queues purged")
    else:
        step(2, "Skipping clean (--no-clean)")

    # Step 3: rebuild
    if not args.no_rebuild:
        step(3, "Rebuild containers")
        rebuild_workers()
        print("  OK ingest + graph-builder rebuilt and restarted")
        time.sleep(5)  # let workers connect
    else:
        step(3, "Skipping rebuild (--no-rebuild)")

    # Step 4: replay
    step(4, f"Replay DARPA THEIA E3 data ({args.limit:,} events)")
    sim_stats = run_simulator(args.limit, args.rate, args.skip_events)
    print(f"  OK Simulator finished in {sim_stats.get('elapsed_s', '?')}s")
    if sim_stats.get("raw_output"):
        print(f"    {sim_stats['raw_output']}")

    # Step 5: drain
    step(5, "Wait for pipeline to drain")
    drain_time = wait_for_drain(timeout=180)
    print(f"  OK Queues drained in {drain_time}s")

    # Step 6: query
    step(6, "Query provenance graph")
    summary = query_graph_summary()
    print(f"  OK {summary['total_nodes']:,} nodes, {summary['total_edges']:,} edges")

    # Step 7: report
    print_report(args, sim_stats, drain_time, summary)


if __name__ == "__main__":
    main()
