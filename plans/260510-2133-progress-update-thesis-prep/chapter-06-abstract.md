# Chapter 6 — Abstract

> Drafted last per the reviewer's instruction. Order of presentation:
> input → scope → result → performance.

## Final abstract (≈ 250 words)

**Input.** This work consumes Splunk Boss of the SOC v2 (BOTSv2) — 188.5
million events across 85+ heterogeneous sourcetypes, replayed through a
real-time pipeline (RabbitMQ → ingest → graph-builder → Neo4j) that converts
raw enterprise telemetry into a 9-label / 14-edge-type provenance graph. Per-
sourcetype parsers handle the dominant high-volume types (`stream_*`, `Sysmon`,
`auditd`, `suricata`, `pan_traffic`, `mysql_*`, `WinRegistry`,
`linux_audit`, `access_combined`, `WinHostMon`).

**Scope.** A hybrid detection layer over the provenance graph: (i) 36 Sigma-
inspired YAML rules adapted for causal edge-pattern matching with per-root-
process finite-state machines, covering 11 MITRE ATT&CK tactics; (ii) a per-
edge LightGBMXT binary classifier trained on IOC-labelled BOTSv2 data, scored
in production by a live RabbitMQ consumer that writes scores and alerts back
to the same graph. Both signals co-annotate the graph and surface through a
React dashboard; Claude Sonnet generates narrative summaries for ML alerts.

**Result.** The thesis contributes: (1) the first reported ML classifier on
BOTSv2 with peer-publishable metrics; (2) honest evaluation methodology
applied to multi-source SIEM telemetry, extending Arp 2022 / Engelen 2021 /
TESSERACT 2019 leakage-prevention practice from network-only datasets to
heterogeneous enterprise telemetry; (3) rule-and-ML co-annotation on a shared
Neo4j provenance graph.

**Performance.** Temporal-split test ROC-AUC = **0.9877** (headline, 39
features) and **0.9135** (honest, 38 features — `sourcetype` excluded).
Per-scenario recall: 99.98 % on the s200 webapp attack; 64.2 % on the s400
APT (temporal-domain-shift gap). The stratified-split reference ceiling
(0.9981) attributes the gap to distribution shift rather than leakage.

---

## Notes for revision

- If word limit is 150: drop the parser list in Input and the rule-tactic count
  in Scope.
- If word limit is 350: add the LLM narrative service and the dashboard's
  endpoint-detail view to Scope.
- "Honest" terminology is from §3.5.1 — if reviewers prefer "ablation-based"
  or "leakage-controlled," swap globally.
- Final numbers should be re-verified against `evaluate.py` output at submission
  time; current values are from the frozen
  `lgbm_xt_temporal` and `lgbm_xt_temporal_no_st` runs in
  `server/ml-engine/botsv2/models/`.

## Unresolved questions

1. Should the abstract name the production scoring service explicitly
   (ml-edge-scorer) or stay at the "live RabbitMQ consumer" level of
   abstraction? Current draft uses the latter for venue-agnosticism.
2. Word limit not yet supplied by the reviewer. Default target is 250 — adjust
   per submission template.
