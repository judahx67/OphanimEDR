# Chapter 4 — Related Studies & Gap Analysis

## 4.1 Provenance-graph threat detection

| System | Approach | Dataset | Limitation this work addresses |
|---|---|---|---|
| **ActMiner** [Ma et al. 2025] | Query graph alignment with Equivalent Semantic Transfer (EST), causal filtering, incremental tree alignment | DARPA TC | Pure pattern-matching; no learned scoring layer for unknown attack variants |
| **KAIROS** [Cheng et al. 2024] | GNN encoder-decoder per-edge anomaly scoring | DARPA TC benchmarks | Requires GPU; opaque scores; not deployable on commodity SIEM telemetry without porting CDM-style schema |
| **MAGIC** [Jia et al. 2024] | Self-supervised masked graph representation learning | 3 real-world/simulated datasets | No labeled-attack supervision exploited; doesn't leverage rule-engine signal as weak labels |
| **SLOT** [Qiao et al. 2025] | Graph reinforcement learning with attack-chain construction | Real-world (undisclosed) | RL training cost; complex deployment; doesn't address heterogeneous SIEM telemetry |
| **Prov2Vec** [Bhattarai & Huang 2023] | Graph kernel → unsupervised anomaly score | Not disclosed | Unsupervised only; no integration with rule-based ground truth |

**Gap:** All five operate on purpose-built audit datasets (DARPA TC) with uniform CDM schemas. None apply provenance-graph reasoning to heterogeneous SIEM telemetry where event semantics vary across 80+ sourcetypes. None combine learned scoring with explicit rule-based weak supervision.

## 4.2 ML on enterprise SIEM telemetry

Direct prior art on **BOTSv2 specifically** is absent. After exhaustive search across arXiv, Google Scholar, IEEE Xplore, USENIX, ACM Digital Library, and GitHub, no peer-reviewed paper trains an ML classifier on BOTSv2 with reported metrics. Existing BOTSv2 use is restricted to:

- Splunk's official Q&A scoring sheet (CTF, no labels per event)
- `ogrodas/BOTSv2-analysis` GitHub repository (exploratory, no ML)
- Splunk vendor blogs (LLM script classification in ES 8.0; no public BOTSv2-specific metrics)

**Why BOTSv2 is rarely used for ML:** (1) no shipped per-event labels, (2) heterogeneous schema requires per-sourcetype engineering, (3) Splunk-bound distribution friction, (4) cleaner alternatives exist (CICIDS2017, UNSW-NB15, TON_IoT).

We position our work methodologically — not as a head-to-head benchmark — against datasets with comparable enterprise-telemetry character that *do* have established ML literature:

| Dataset | Best published in-domain | Cross-domain transfer |
|---|---|---|
| CICIDS2017 / CSE-CIC-IDS2018 | RF/XGBoost 95–99% F1 | Substantial degradation [Engelen 2021] |
| UNSW-NB15 | RF 95.08% | UNSW→TON_IoT drops to <40% |
| TON_IoT | RF ~99.79% | TON_IoT→UNSW drops to <40% |

### 4.2.1 Feature comparison with prior datasets

The classifiers cited above operate on **network-flow features only**. BOTSv2
adds endpoint and identity telemetry that no single benchmark exposes — which
is why direct head-to-head comparison is methodological, not numeric. The
overlap and divergence are:

| Feature family | CICIDS2017 | UNSW-NB15 | TON_IoT | **This work (BOTSv2)** |
|---|---|---|---|---|
| Network 5-tuple (src/dst IP+port, proto) | ✓ flow-derived | ✓ flow-derived | ✓ flow-derived | ✓ from `stream:tcp/udp` |
| Flow duration / bytes / packets | ✓ (80+ flow stats) | ✓ (49 features) | ✓ | ✓ subset (12 numeric) |
| TCP flag counts | ✓ | ✓ | ✓ | ✗ (not extracted) |
| HTTP method / URI / UA | partial | ✗ | ✓ | ✓ (`stream:http`, `access_combined`) |
| DNS query / response | partial | ✗ | ✓ | ✓ (`stream:dns`) |
| Process / parent process | ✗ | ✗ | partial (host telemetry) | ✓ (`Sysmon`, `auditd`) |
| File create / write / read | ✗ | ✗ | partial | ✓ (Sysmon EID 11, auditd) |
| Registry modification | ✗ | ✗ | ✗ | ✓ (`WinRegistry`, Sysmon EID 12/13) |
| Authentication events | ✗ | ✗ | partial | ✓ (`linux_audit`) |
| IDS-rule alert signature | ✗ | ✗ | ✗ | retained for ablation, dropped at train |
| **Graph triple** (subject_type, edge_type, object_type) | ✗ | ✗ | ✗ | **✓ — novel feature in this work** |
| **Sourcetype / log-source label** | ✗ (single tap) | ✗ (single tap) | ✗ (single tap) | **✓ — the headline-vs-honest pivot** |

**Why the comparison datasets do not have a "sourcetype" feature:**
CICIDS/UNSW/TON_IoT are collected from a single capture point each. Every row
in CICIDS2017 is a CICFlowMeter-derived row; every row in UNSW-NB15 is an Argus
flow record. There is no internal label that says "this came from the HTTP
parser vs the DNS parser" — there's only one parser. BOTSv2 is structurally
different: 85+ Splunk sourcetypes are multiplexed into one event stream, and
`sourcetype` is the demultiplexer.

**Why Engelen 2021's port-drop is the right analog:**
CICIDS's `Destination Port` plays the same role as BOTSv2's `sourcetype` —
it identifies the flow's protocol family and is assigned at capture, not
derived from behaviour. Engelen showed that keeping `Destination Port`
inflated CICIDS classifiers' accuracy because the model learned a port-to-class
mapping rather than behavioural signal. Dropping `sourcetype` here removes the
exact same shortcut on a structurally larger label space.

**Gap:** Published in-domain numbers on CICIDS/UNSW/TON_IoT are inflated by
routing/identity features that fail to transfer cross-dataset. None apply
provenance-graph context (subject → edge → object triple) as features. This
work addresses both: a graph-aware feature schema, and explicit reporting of
headline-vs-honest variants for the most powerful routing feature in the
schema.

## 4.3 Data leakage in security ML

| Paper | Contribution | How this work applies it |
|---|---|---|
| **Arp et al. 2022** ("Dos and Don'ts of ML in Security") | Defines pitfall taxonomy P1–P10; P4 = Spurious Correlations | Sourcetype as routing label is the canonical P4 example; honest variant addresses this |
| **Pendlebury et al. 2019** ("TESSERACT") | Spatial + temporal experimental bias; AUT metric for honest reporting | Temporal split mirrors TESSERACT temporal-bias protocol; stratified split = oracle upper bound |
| **Engelen et al. 2021** ("Troubleshooting CICIDS2017") | Drops `Destination Port` because flow-defining identifier, not behavior | Direct precedent: same logic applied to `sourcetype` |
| **Catillo et al. 2023** ("Faulty use of CIC-IDS 2017") | Quantifies AUC/F1 cost of removing identity features | Format precedent for our ablation table |
| **Apruzzese et al. 2023** (SoK) | Argues for "deployment-realistic" reporting | Justifies dual-model report (headline + honest) |
| **Kaufman et al. 2012** ("Leakage in Data Mining") | Foundational leakage taxonomy | Citation for `_time`, `host`, `scenario` drop justifications |
| **Sommer & Paxson 2010** ("Outside the Closed World") | Argues domain context is necessary for interpretable NIDS | Steel-man counter-argument addressed in Discussion |

**Gap filled:** Prior leakage-aware work focuses on network IDS (CICIDS, UNSW). We extend the methodology to multi-source SIEM telemetry where the "routing label" (sourcetype) plays the analogous role of `Destination Port` in CICIDS.

## 4.4 Rule-based detection systems

Sigma rules [SigmaHQ 2017–present] provide a portable YAML-based rule format for SIEM detection. Our rule engine adapts 36 Sigma-inspired rules across 11 MITRE ATT&CK tactics to operate on the provenance graph rather than raw events: each rule condition tests one causal edge (subject-edge-object), and `sequence` rules use a per-root-process FSM to detect ordered causal chains within a time window.

**Gap:** Sigma rules execute against raw event streams; they don't naturally express causal chains. Our edge-pattern + FSM extension is, to our knowledge, novel for Sigma-style rules on a Neo4j provenance graph.

## 4.5 Hybrid rule + ML detection

| System | Rule + ML pattern |
|---|---|
| HOLMES, SLEUTH | Rule-only, scenario-graph based |
| ActMiner | Rule-only with weak ML for path scoring (limited integration) |
| KAIROS | ML-only (GNN), no rule layer |
| **This work** | Rules + ML co-write the same Neo4j graph; both contribute orthogonal evidence to incident view |

**Gap:** No prior system integrates rule-based and ML-based detection at the storage layer with both annotating the same provenance graph in real-time. Our `Incident` nodes (rule-derived) and edge-level ML scores (`botsv2_ml_score`, `botsv2_ml_score_honest`) co-exist on the same graph, enabling analyst dashboards to surface both signals on identical entities.

## 4.6 Summary

This work fills three gaps in the related literature:

1. **First reported ML classifier on BOTSv2** — addresses the dataset-availability gap (no public labels, no ML benchmarks).
2. **Honest evaluation methodology applied to heterogeneous SIEM telemetry** — extends Arp/TESSERACT/Engelen leakage-prevention precedent from network-only datasets (CICIDS, UNSW) to multi-source enterprise telemetry.
3. **Rule + ML co-annotation on a shared provenance graph** — first integration of Sigma-style rules and edge-level ML scoring on the same Neo4j-backed graph, with LLM narrative generation closing the explainability loop.
