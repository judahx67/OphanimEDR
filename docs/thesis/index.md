# Thesis Report — Master Index

**Title:** Applying Causality Tracking and Incremental Alignment for Graph-Based Threat Hunting  
**Dataset:** Splunk BOTSv2 (188.5M events, 85+ sourcetypes)  
**Last updated:** 2026-05-16 (post Stream A+C retrain)

## Report chapters

| File | Status | Notes |
|---|---|---|
| [chapter-01-introduction.md](chapter-01-introduction.md) | ✅ current | RQs still valid |
| [chapter-02-overview.md](chapter-02-overview.md) | ✅ current | Architecture diagram correct |
| [chapter-03-methodology.md](chapter-03-methodology.md) | ✅ updated | IOC tightening + new AUC numbers |
| [chapter-04-related-studies.md](chapter-04-related-studies.md) | ✅ current | Gap analysis still holds |
| [chapter-05-conclusion.md](chapter-05-conclusion.md) | ✅ updated | New AUC numbers + revised RQ answers |
| [chapter-06-abstract.md](chapter-06-abstract.md) | ⚠️ needs update | Still has old AUC numbers |

## Key reference docs

| File | Purpose |
|---|---|
| [ml-pipeline-spec.md](ml-pipeline-spec.md) | Complete ML spec: data, labeling, features, splits, results |
| [system-architecture.md](system-architecture.md) | Current stack (BOTSv2, not THEIA) |

## Evidence artifacts (plans/reports/)

| File | Purpose |
|---|---|
| `plans/reports/audit-260515-2004-iocs-yaml-verification.md` | Per-IOC corpus scan evidence (173K vs 2.15M positives) |
| `plans/reports/audit-260515-2004-ml-and-labels-rethink.md` | Label leakage diagnosis |
| `plans/reports/audit-260515-1921-defense-readiness.md` | Full defense readiness audit |
| `plans/reports/research-260510-2133-binary-classifier-prior-art-and-leakage-precedent.md` | Leakage precedent (Arp/TESSERACT/Engelen) |

## Current model numbers (post Stream A+C+external_ip)

| Model | AUC | Use |
|---|---|---|
| `lgbm_xt_temporal` | **0.9530** | Production / demo |
| `lgbm_xt_temporal_no_st` | 0.5544 | Ablation reference |
| `lgbm_xt_stratified` | 0.9999 | Capability upper bound |
| `lgbm_xt_stratified_no_st` | 0.9853 | Honest upper bound |
