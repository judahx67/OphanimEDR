# Progress Report — Honest Evaluation of FLASH GNN on DARPA TC E3 THEIA

**Date:** 2026-05-31 · **Branch:** `feature/migrate-to-gnn-w2v-theia`

## Summary
Wired our retrained FLASH GNN (GraphSAGE + Word2Vec, v3 weights) into the live
detection pipeline and audited it honestly against ground truth. The published
F1 ≈ 0.96 reproduces, but it is a **2-hop evaluation artifact**: raw node-level
F1 is **0.77**, and the actual intrusion (the implant process) is **not detected**.
The high score reflects flagging the attack's *network neighbourhood*, not the actor.

## Verified findings

**1. THEIA E3 ground truth is a netflow blob.** Of 25,358 labelled-malicious UUIDs:
NetFlowObject **99.7%** (25,291), SUBJECT_PROCESS **0.1%** (23), File 5.
*(verified: `data_files/theia.json` ∩ CDM types)*

**2. The headline 0.96 is the 2-hop adjustment, not detection.**
Same model, three numbers (full held-out split `6r.json.8`):
| Evaluation | Precision | Recall | F1 |
|---|---|---|---|
| RAW (faithful, node-level) | 0.81 | 0.73 | **0.768** |
| 2-hop adjusted (FLASH's own method) | 0.93 | 0.998 | **0.965** |

The adjustment forgives **2,424** false positives (within 2 hops of any GT node)
and promotes **6,874** misses to hits. On a dense netflow graph, 2 hops reaches
almost everything. *(verified: `_verify_gnn.py`, a re-instrumented copy of FLASH's
own `Theia.ipynb` `helper()`)*

**3. The gap is not flagged in any official script.** FLASH's released `helper()`
computes raw TP/FP/FN, then **overwrites them** with the 2-hop values on the next
line and prints **only** the adjusted metric. The raw node-level number is never
reported upstream — we expose it.

**4. The implant is never found.** In the live pipeline run, **0 of 21** in-graph
GT processes were flagged; **96%** of all flagged nodes are netflow/Socket. The
system detects the attack's network region, which the metric credits as 0.96 —
but for an EDR (which must act on a specific process) that is insufficient.

## System status
End-to-end live path works: THEIA replay → ingest → Neo4j → full-graph GNN scorer
(mirrors `evaluate.py`) → dashboard. Demonstrates the behaviour on real attack
data (900k-edge attack window, 25,315 GT nodes present).

## Conclusion & recommendation
Node-level recall on THEIA is a **netflow artifact**; the dataset has no
process/incident-level labels, so implant-level detection cannot be learned or
measured here. **Recommend pivot to DARPA OpTC** (per-action red-team labels,
process-level) where node detection is operationally meaningful and the 2-hop
adjustment does less lifting. **Verify OpTC's GT composition first** (same
breakdown) before committing — THEIA looked clean until we computed it.

**Thesis contribution framing:** honest re-evaluation of a provenance IDS —
exposing that the headline metric is a neighbourhood-tolerance artifact and that
node-level scores do not imply actor-level detection.

## Unresolved questions
- OpTC GT composition — process-level as expected? (verify before pivot)
- Recover process-level detection via seed→owning-process grouping (seeds are
  1-hop from the implant) — pursue, or accept host-IDS framing?
