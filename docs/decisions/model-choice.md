# Decision: Deploy the Honest (No-Sourcetype) Model for Alerting

## What

The `ml-edge-scorer` writes **both** scores to every edge in Neo4j (`botsv2_ml_score` and `botsv2_ml_score_honest`) but the **honest model alone** decides whether an edge becomes an alert. The headline model is retained as a comparison artefact and dashboard column; it does not trigger LLM analysis.

## Why — the apparent paradox

| Metric | Headline (with sourcetype) | Honest (no sourcetype) |
|---|---|---|
| ROC-AUC | **0.9530** | 0.5544 |
| Precision @ F1-optimal threshold | 0.608 | **0.9977** |
| Recall @ same | 0.204 | 0.187 |
| F1 | 0.305 | **0.315** |
| **False Positives (1M test events)** | **7,024** | **23** |
| True Positives | 10,893 | 9,989 |

The headline model has dramatically higher AUC but the honest model has **305× fewer false positives** at virtually identical recall.

## Why sourcetype dominates (and why it shouldn't)

Per-sourcetype label rate in the training set:

| Sourcetype | Positive rate | Rationale |
|---|---|---|
| `apache_error` | **94.0%** | WAF errors fire during SQL injection window |
| `stream_http` | 23.8% | HTTP traffic contains attack payloads |
| `stream_smb` | 22.4% | SMB traffic in lateral movement window |
| `ps` | 27.1% | Process snapshots during attack |
| 30+ other sourcetypes (Perfmon, WinEventLog, etc.) | **0.0%** | Never carry IOCs |

So `sourcetype=apache_error` alone implies ~94% malicious probability. Feature-importance ranking confirms this:

| Feature | Gain importance |
|---|---|
| `external_ip` | 44.0% |
| `sourcetype` | 27.7% |
| `dest_port` | 17.3% |
| `command_line` | 5.5% |
| All others | < 6% combined |

This means the headline model is not learning attack *behaviour* — it is learning *"which log channels happened to be noisy during the attack window."* In a real deployment, the log channels don't shift; only the content does. So the sourcetype prior is **label-distribution leakage**, not signal.

## The AUC paradox explained

AUC measures cross-threshold ranking quality across **all** events. The honest model's score distribution is narrow — most events score near 0, only a handful score high. So AUC suffers (poor ranking spread between low-confidence-benign and low-confidence-malicious) but precision at any threshold is excellent.

The headline model spreads scores across the [0, 1] range using sourcetype as the spreading axis. Good AUC, bad precision: it confidently flags entire log channels.

**Practically:** AUC is misleading here. F1 is the right metric, and F1 is *slightly higher* on the honest model.

## Per-sourcetype recall is equivalent

Crucial check: per-sourcetype recall on the test set is nearly identical between models:

| Sourcetype | Headline recall | Honest recall | Δ |
|---|---|---|---|
| stream_mysql | 1.0000 | 1.0000 | 0 |
| stream_http | 1.0000 | 1.0000 | 0 |
| stream_tcp | 0.9035 | 0.8881 | -0.015 |
| stream_ip | 0.9993 | 0.9359 | -0.063 |
| access_combined | 1.0000 | 1.0000 | 0 |
| pan_traffic | 0.0173 | 0.0173 | 0 |
| suricata | 0.0639 | 0.0640 | +0.0001 |

The two models detect the same attacks within each sourcetype. The headline model only adds a cross-sourcetype prior that does not improve detection — it inflates FP count and AUC simultaneously.

## Alternatives considered

| Option | Rationale | Decision |
|---|---|---|
| Headline-only | Best AUC | **Rejected** — 7,024 FPs is operationally unusable; FPs cluster on victim infrastructure (see `labelling.md`) |
| Honest-only (chosen) | Best precision; F1 ≥ headline; clean defense story | **Accepted** |
| OR both | Maximum recall | Rejected — was the previous default; produced the brewertalk.com FP cluster |
| AND both | Maximum precision | Rejected — pointless, since honest already has 99.77% precision alone |
| Per-sourcetype models | Eliminates the prior properly | Deferred — significant retraining work; honest single-model achieves the same operational goal |

## Implementation

```python
# server/ml-edge-scorer/main.py
score_headline = headline_model.predict_proba(feature_row)
score_honest = honest_model.predict_proba(feature_row)

is_alert = score_honest >= threshold_honest  # honest decides alerting

# Both scores still written to Neo4j for comparison + dashboard display
```

The headline model artefact is retained in `models/lgbm_xt_temporal/` for the thesis comparison narrative. Removing it would discard the AUC contrast that makes the leakage argument concrete.

## Thesis framing implication

This decision strengthens the thesis story:

- "Our deployed ML model achieves 99.77% precision on held-out temporal test data."
- "The high-AUC sourcetype-inclusive variant is presented as evidence that AUC is a misleading metric in this setting — sourcetype acts as a categorical prior that inflates ranking quality while degrading practical precision."
- "Operational detection is the honest model; the LLM analyser layer triages its 23-FP rate down to actionable incidents."

## Sources

- `models/lgbm_xt_temporal/test_metrics.json`
- `models/lgbm_xt_temporal_no_st/test_metrics.json`
- `models/lgbm_xt_temporal/eval/summary.json`
- Live feature importance via `booster.feature_importance(importance_type='gain')`
- Per-sourcetype label distribution: `data/temporal/train.parquet` groupby
