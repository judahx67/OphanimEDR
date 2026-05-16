# Decision: Alert Threshold

## What

The `ml-edge-scorer` service assigns each provenance edge a probability score (0–1) from
the `lgbm_xt_temporal` (headline) and `lgbm_xt_temporal_no_st` (honest) models.
An edge is flagged as an alert — and published to the `ml_alerts` queue for LLM analysis —
if either score exceeds the deployment threshold.

**Chosen thresholds (read from each model's `threshold.json`):**

| Model | Threshold | Val precision | Val recall |
|---|---|---|---|
| `lgbm_xt_temporal` (headline) | **0.05** | 0.754 | 0.252 |
| `lgbm_xt_temporal_no_st` (honest) | **0.05** | — | — |

The threshold was selected to maximise F1 on the temporal validation set.

## Why not a higher precision threshold?

The temporal domain shift makes 99%-precision thresholds impractical.
On the val set, sweeping thresholds yields:

| Threshold | Val alerts | Val precision | Val recall |
|---|---|---|---|
| 0.05 | ~260K | 0.754 | 0.252 |
| 0.50 | 10,137 | 0.708 | 0.083 |
| 0.90 | 2,904 | 0.029 | 0.001 |
| 0.99 | 74 | 0.000 | 0.000 |

Precision actually *falls* above t=0.5 because the high-confidence region in val is
dominated by benign events that happen to cluster near the attack-time period
(confirmed by score histogram: the model's max val score is 0.9991, but these top
scores are false positives from activity concurrent with the attack window).

Root cause: s400 APT positives are labeled by a C2 IP (45.77.65.211). During training
(earliest 60% of timeline) this IP appears as `src_ip`; in val/test it appears as
`dest_ip`. Because the model was retrained with `external_ip` (direction-independent),
this should improve but the val domain shift is still present.

## Alternatives considered

| Option | Rationale | Rejected because |
|---|---|---|
| Fixed 0.9 / 0.7 (original hardcoded) | Conservative alerting | Precision collapses above 0.5 — 97% FP at t=0.9 |
| 0.99 precision target | Minimal analyst fatigue | Zero recall; no alerts in demo |
| F1-optimal (chosen) | Balanced — highest combined precision+recall | Accepted |

## Alert volume in practice

The deduplication cache in `llm-analyzer` (5-minute TTL per `(subj, obj, edge_type)`)
prevents LLM floods even at the lower threshold. Only the first occurrence of each pattern
within the window triggers a Gemini call; subsequent identical alerts are counted and
suppressed.

## How to adjust

Override via environment variable if a different balance is needed for a specific demo:
```bash
ML_THRESHOLD_HEADLINE=0.5  # docker-compose.yml env block
ML_THRESHOLD_HONEST=0.5
```
