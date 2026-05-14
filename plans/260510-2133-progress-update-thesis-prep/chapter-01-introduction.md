# Chapter 1 — Introduction

## 1.1 Problem Statement

Modern enterprises generate terabytes of security telemetry daily across heterogeneous sources (network sensors, OS audit logs, web servers, database logs, endpoint detection agents). Security Operations Centers (SOCs) face two compounding pressures: (a) the volume of events vastly exceeds analyst review capacity, and (b) Advanced Persistent Threats (APTs) deliberately blend their actions into ordinary system activity, making rule-based detection insufficient on its own. Existing detection systems either rely on manually authored rules — which miss novel attacks — or apply machine learning to narrow log types — which fail to integrate the cross-source context analysts depend on.

## 1.2 Motivation

Two observations motivate this work:

1. **Provenance graphs unify heterogeneous telemetry.** The same conceptual model — entities (Process, File, Socket, Host, User) connected by causal edges (FORK, EXEC, READ, WRITE, CONNECT, ACCESS) — applies whether the underlying data is a DARPA CDM stream, a Sysmon event, or a Splunk Stream:HTTP record. A unified provenance graph enables analysis that is otherwise siloed by source.

2. **Hybrid rule + ML detection compounds strengths.** Rules provide explainable, high-precision detection of known attack patterns; ML provides coverage of unknown variants. Rules can also serve as weak supervision signal for ML training. Neither approach individually achieves both coverage and explainability.

## 1.3 Research Questions

- **RQ1**: Can a per-edge binary classifier trained on enterprise SIEM telemetry (Splunk BOTSv2) achieve detection performance comparable to provenance-graph baselines on purpose-built audit datasets (DARPA TC), under temporally-honest evaluation?
- **RQ2**: How much of the apparent classifier accuracy comes from genuine behavioral signal versus routing/identity metadata (sourcetype, host, IP)? What is the cost of removing all suspect features?
- **RQ3**: Does a dual-layer architecture (rule engine + ML scoring) provide measurable improvements over either approach alone?

## 1.4 Contributions

1. **First reported ML classifier on BOTSv2.** No peer-reviewed prior art exists; we contribute a reusable IOC-based labeling pipeline (`label.py` + `iocs.yaml`) and a 39-feature schema (`schema.py`) that turns 188.5M raw Splunk events into a labeled binary classification dataset.

2. **Honest evaluation methodology with quantified leakage.** We report two model variants: a *headline* model including sourcetype (ROC-AUC 0.9877) and an *honest* model excluding it (ROC-AUC 0.9135). The 8.7 pp gap quantifies the contribution of the routing-label feature. We additionally compare temporal versus stratified splits to expose distribution-shift effects (0.9981 stratified upper bound vs 0.9877 temporal).

3. **End-to-end production pipeline.** A live containerized stack (RabbitMQ, Neo4j, FastAPI, React) consumes events, builds the provenance graph, applies 36 Sigma-style rules, scores each edge with both ML variants, and presents incidents to analysts via a dashboard. The system supports per-edge scoring at production rate.

4. **LLM-augmented incident analysis.** Edges flagged by either ML model trigger Claude-Sonnet narrative generation against the 2-hop subgraph context, producing analyst-readable explanations rather than opaque scores.

## 1.5 Thesis Organization

Chapter 2 surveys related work in provenance-graph threat detection and machine learning for intrusion detection. Chapter 3 presents the system architecture. Chapter 4 details the BOTSv2 data pipeline. Chapter 5 presents the feature engineering and leakage-prevention methodology. Chapter 6 documents model training and hyperparameter justification. Chapter 7 evaluates classifier performance. Chapter 8 discusses findings and limitations. Chapter 9 concludes with future directions.
