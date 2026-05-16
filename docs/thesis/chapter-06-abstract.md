# Chapter 6 — Abstract

## Final abstract (≈ 250 words)

**Input.** This work consumes Splunk Boss of the SOC v2 (BOTSv2) — 188.5 million events across 85+ heterogeneous sourcetypes, replayed through a real-time pipeline (RabbitMQ → ingest → graph-builder → Neo4j) that converts raw enterprise telemetry into a 9-label / 14-edge-type provenance graph. Per-sourcetype parsers handle the dominant high-volume types (`stream_*`, `Sysmon`, `auditd`, `suricata`, `pan_traffic`, `mysql_*`, `WinRegistry`, `linux_audit`, `access_combined`, `WinHostMon`).

**Scope.** A hybrid detection layer over the provenance graph: (i) 36 Sigma-inspired YAML rules adapted for causal edge-pattern matching with per-root-process finite-state machines, covering 11 MITRE ATT&CK tactics; (ii) a per-edge LightGBMXT binary classifier trained on IOC-labeled BOTSv2 data, scored in production by a live RabbitMQ consumer that writes scores and alerts back to Neo4j edges; (iii) an LLM narrative generator (Gemini) that produces analyst-readable forensic summaries for high-confidence ML alerts.

**Label methodology.** Per-event labels are derived by IOC substring matching against empirically-verified indicators. Each IOC was validated by full-corpus hit-count scan; over-broad indicators (victim domains, shared infrastructure IPs) were removed, reducing positive labels from 2.15M to 173K (−12.4×) and eliminating label inflation that distorted earlier AUC estimates.

**Performance.** The headline model (`lgbm_xt_temporal`, 42 features including sourcetype and direction-independent `external_ip`) achieves ROC-AUC **0.9530** on a temporally-honest test split (trained Aug 11–20, tested Aug 25+). A stratified upper-bound model reaches 0.9999, confirming the temporal gap reflects domain shift rather than model incapacity. A no-sourcetype ablation (0.5544) quantifies the routing-label contribution. Per-scenario recall on the stratified split: s200 webapp 95.1%, s300 ransomware 88.5%, s400 APT 91.7%.
