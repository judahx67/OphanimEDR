# Phase 01 — Pipeline Container

## Overview

Build a single `pipeline` image that runs ingest + graph-builder + rule-engine + ml-edge-scorer under supervisord. Each worker stays as its own Python process; no code changes to `main.py` files.

Priority: P0 · Status: pending

## Key Insights

- Each worker's `main.py` is already a long-running `while True` consumer. Supervisord can launch them as-is with `python -u main.py`.
- Dependencies overlap heavily (pika, neo4j-python-driver). Merging requirements files dedupes them.
- ml-edge-scorer needs LightGBM + the `botsv2_parsers` module from the repo root; ingest also imports from repo root. Unified Dockerfile uses `server/` as build context.
- Each worker reads env vars (RABBITMQ_HOST, NEO4J_URI, etc.). These stay in compose and apply to all 4 supervisord children via the container env.

## Files

**Create:**
- `server/pipeline/Dockerfile` — multi-stage build, copies all 4 worker dirs + shared modules, installs merged requirements
- `server/pipeline/requirements.txt` — union of the 4 worker requirements (pin via existing files)
- `server/pipeline/supervisord.conf` — 4 program blocks, autorestart=true, stdout/stderr → container logs

**Leave alone:**
- `server/{ingest,graph-builder,rule-engine,ml-edge-scorer}/main.py` and their Dockerfiles (the old Dockerfiles stay on disk through phase 03; deleted in a later cleanup commit)

## Implementation Steps

1. Write `server/pipeline/requirements.txt` by reading each worker's `requirements.txt` and taking the union (highest pinned version when conflicts).
2. Write `server/pipeline/Dockerfile`:
   - `FROM python:3.12-slim`
   - Install supervisor (`apt-get install -y --no-install-recommends supervisor`)
   - `COPY server/ingest server/graph-builder server/rule-engine server/ml-edge-scorer server/botsv2_parsers /app/`
   - Each worker lands at `/app/<name>/`
   - `pip install -r /app/pipeline/requirements.txt`
   - `CMD ["supervisord", "-c", "/app/pipeline/supervisord.conf", "-n"]`
3. Write `server/pipeline/supervisord.conf` with 4 `[program:*]` blocks, each `command=python -u main.py`, `directory=/app/<worker>`, `stdout_logfile=/dev/fd/1`, `stderr_logfile=/dev/fd/2`, `stdout_logfile_maxbytes=0`.
4. `docker build` it locally and confirm the image builds clean. Don't wire into compose yet — that's phase 02.

## Todo

- [ ] requirements.txt union
- [ ] Dockerfile
- [ ] supervisord.conf
- [ ] Local `docker build` succeeds

## Success Criteria

- `docker build -t edr-pipeline -f server/pipeline/Dockerfile server/` exits 0
- Running the image manually (without compose) starts all 4 supervisord children and they log their expected "waiting for rabbitmq" or "connected" messages when env vars point at a live stack

## Risks

- **ml-edge-scorer model mount:** the models dir must mount into the pipeline container at the same path the scorer expects (`MODELS_DIR=/app/models`). Compose handles this in phase 02.
- **Import-path drift:** ingest and ml-edge-scorer import `botsv2_parsers` from a sibling dir. Verify import resolution after the copy.
- **One worker crash takes down the container** if supervisord's `autorestart` isn't set — must be `autorestart=true` and `startretries=10`.
