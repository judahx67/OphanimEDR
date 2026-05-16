# Decision: Two Detection Paths

## What

The pipeline runs two complementary detectors in parallel:

| Detector | Source tag | Mechanism | Output |
|---|---|---|---|
| Rule engine | `rule-engine` | 36 Sigma-inspired YAML rules; FSM causal-chain matching | `:Incident` node with MITRE tag |
| ML + LLM | `ml-llm` | LightGBMXT per-edge scorer; Gemini narrative on flagged edges | `:Incident` node with LLM analysis |

Both write `:Incident` nodes to Neo4j. The `source` property distinguishes them.
The dashboard surfaces both with a source badge per incident.

## Why both?

**Rules = deterministic recall on known tactics.**
The 36 YAML rules cover 11 MITRE tactics explicitly. Each rule is readable, auditable,
and fires with 100% confidence on exact pattern matches. A human can inspect the YAML
and understand exactly why an alert fired.

**ML = generalisation beyond enumerated patterns.**
The LightGBMXT model was trained on 5.2M labelled edges (173K positive) and learns
statistical co-occurrence patterns across 42 features. It can flag behaviours that no
rule covers — e.g. unusual process-file interaction patterns outside the known tactic list.

**Why not ML only?**
ML produces a probability, not an explanation. Without rules, there is no deterministic
ground truth to anchor the LLM narrative or validate against known-bad signatures.
Rules also serve as positive-label generators during training (see `label.py`).

**Why not rules only?**
Rules enumerate known patterns. Novel or obfuscated variants (e.g. renamed tools,
non-standard ports) evade enumeration. ML generalises from the feature distribution.

## Agreement table (offline estimate, BOTSv2 test set)

| | Rule fires | Rule silent |
|---|---|---|
| **ML alert** | Both agree — highest confidence | ML-only: novel pattern or enumeration gap |
| **ML silent** | Rule-only: exact match, ML didn't generalise | Neither: benign or missed by both |

When both detectors agree on the same edge, analysts should treat that as highest
confidence. Dashboard can filter on `source = 'rule-engine' AND 'ml-llm'` overlap.

## Implementation notes

- Rule incidents: written by `server/rule-engine/main.py`, keyed by `incident_id` (UUID).
- ML incidents: written by `server/llm-analyzer/main.py`, keyed by `event_id` (edge UUID).
- Both use `MERGE` so replays don't create duplicates.
- Rules consume from `normalized_events` queue. Scorer consumes from `normalized_events_scoring` (private fanout copy).
