# Phase 02 — Compose Refactor

## Overview

Replace the 4 worker services in `server/docker-compose.yml` with a single `pipeline` service. Add memory limits and drop `container_name:` lines so the stack can run side-by-side with other deployments.

Priority: P0 · Status: pending

## Files

**Modify:**
- `server/docker-compose.yml`

**No deletions yet.** Old worker Dockerfiles stay on disk until phase 03 passes — easy rollback.

## Implementation Steps

1. Remove services: `ingest`, `graph-builder`, `rule-engine`, `ml-edge-scorer`.
2. Add `pipeline` service:
   ```yaml
   pipeline:
     build:
       context: .
       dockerfile: pipeline/Dockerfile
     environment:
       RABBITMQ_HOST: rabbitmq
       RABBITMQ_PORT: 5672
       RABBITMQ_USER: guest
       RABBITMQ_PASS: guest
       NEO4J_URI: bolt://neo4j:7687
       NEO4J_USER: neo4j
       NEO4J_PASS: edr-thesis
       SOURCE_FORMAT: ${SOURCE_FORMAT:-botsv2}
       BATCH_SIZE: 200
       BATCH_TIMEOUT: 2.0
       MODELS_DIR: /app/models
       ML_THRESHOLD_HEADLINE: "0.9"
       ML_THRESHOLD_HONEST: "0.7"
     volumes:
       - ./ml-engine/botsv2/models:/app/models:ro
     depends_on:
       rabbitmq: { condition: service_healthy }
       neo4j:    { condition: service_healthy }
     mem_limit: 2g
     restart: unless-stopped
   ```
3. Add `mem_limit` to the other services as guardrails:
   - rabbitmq: 1g · neo4j: 2g · api: 512m · dashboard: 256m
4. Drop every `container_name:` line so multiple stacks can coexist (compose auto-names from project + service).
5. Update the header comment to reflect the new 5-service topology.
6. Default `SOURCE_FORMAT` flips from `theia` to `botsv2` (matches current actual use; THEIA is archived).

## Todo

- [ ] Remove 4 worker service blocks
- [ ] Add `pipeline` block
- [ ] Add `mem_limit` to all services
- [ ] Strip `container_name:` lines
- [ ] Update header diagram + comments
- [ ] `docker compose config` validates clean

## Success Criteria

- `docker compose config` exits 0 and shows pipeline + 4 other services
- `docker compose up -d` brings the stack healthy within 60s
- `docker compose ps` shows pipeline running
- `docker compose logs pipeline` shows all 4 supervisord children connected to rabbitmq + neo4j

## Risks

- **Build context change:** pipeline builds from `server/` (same as ingest/ml-edge-scorer already do). graph-builder and rule-engine previously built from their own dirs — verify nothing in those dirs assumes CWD.
- **Model volume path:** `./ml-engine/botsv2/models` is relative to `server/` (compose file location). Keep identical to the current ml-edge-scorer mount.
