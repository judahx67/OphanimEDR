# Binary Classifier Prior Art & Leakage Precedent for BOTSv2 Thesis

**Date:** 2026-05-10
**Scope:** Synthesis of two research crawls — (1) prior ML classifiers on BOTSv2 / similar datasets, (2) precedent for dropping routing/metadata features
**Purpose:** Foundation for thesis Related Work + Methodology chapters

---

## 1. Headline Findings

### Finding 1: BOTSv2 has no peer-reviewed ML prior art
After exhaustive search (arXiv, Google Scholar, IEEE, USENIX, ACM, GitHub), **zero academic ML papers train classifiers on BOTSv2 with reported metrics**. BOTSv2 is used as SOC training / CTF dataset, not an ML benchmark.

**Implication for thesis:** Frame this as "first reported ML classifier on BOTSv2." No direct baseline → reposition comparison against analogous enterprise-telemetry datasets.

### Finding 2: Sourcetype-drop has strong direct precedent
Multiple high-impact papers explicitly drop routing / identity / metadata features and report the AUC cost. The 0.9877 → 0.9135 "honest" framing is canonical practice (TESSERACT, Arp et al. P4).

**Implication for thesis:** Methodologically defensible. Cite Arp (P4 Spurious Correlations), TESSERACT (temporal/spatial bias), Engelen 2021 (port-drop on CICIDS2017).

---

## 2. Prior Art on BOTSv2 (and analogous datasets)

### 2.1 BOTSv2 — what exists
| Source | Type | ML metrics? |
|---|---|---|
| `splunk/botsv2` (official) | Dataset release | None — Q&A scoring sheet only |
| `ogrodas/BOTSv2-analysis` GitHub | Exploratory analysis | None |
| Splunk ES 8.0 ML blog | Vendor blog | None public; LLM script classifier (no BOTSv2-specific numbers) |
| BOTES Dataset gitbook | Catalogue | Pure CTF framing |

**Why BOTSv2 is rarely used for ML:** (1) no shipped labels (CTF scoring sheet only), (2) heterogeneous schema needing per-sourcetype parsers, (3) Splunk-bound distribution friction, (4) cleaner alternatives exist (CICIDS2017).

### 2.2 Analogous datasets with strong ML literature
Position your work methodologically against these — not as dataset replacements but as comparable telemetry-classification problems.

| Dataset | Why analogous | Representative result |
|---|---|---|
| **CICIDS2017 / CSE-CIC-IDS2018** | Multi-sourcetype enterprise traffic, labeled scenarios | RF/XGBoost 95–99% F1 in-domain; collapses cross-domain |
| **UNSW-NB15** | 9 attack families, 49 features, host+network | RF 95.08% in-domain |
| **TON_IoT** | Heterogeneous sources (Win/Linux + network + IoT) — closest in *shape* to BOTSv2 mixed sourcetypes | RF ~99.79% in-domain, <40% cross-domain |
| **DARPA TC E3 (THEIA / CADETS)** | Provenance-graph telemetry — used by ActMiner, KAIROS, MAGIC, SLOT | Ref [1]–[5] in CLAUDE.md |
| **EVTX-ATTACK-SAMPLES** | MITRE-tagged Windows event logs | Mostly used for rules, not ML |

**Cross-domain transfer evidence (cite for honest evaluation argument):** UNSW↔TON_IoT cross-dataset experiments show RF dropping >99% → <40% — direct evidence that high in-domain AUC ≠ generalization.

---

## 3. Precedent for Dropping Routing / Metadata Features

### 3.1 Strongest references (ranked by relevance)

| # | Paper | Venue | Key contribution |
|---|---|---|---|
| 1 | **Arp et al. 2022** — "Dos and Don'ts of ML in Computer Security" | USENIX Security | Defines **Pitfall P4 (Spurious Correlations)**: features that encode collection environment cause inflated metrics. Found in ≥73% of reviewed papers. Direct match to your sourcetype as routing-label argument. |
| 2 | **Pendlebury et al. 2019** — "TESSERACT" | USENIX Security | **Spatial + temporal bias** framework. Introduces **AUT metric** as honest replacement for inflated AUC/F1. Your temporal vs stratified split = exact TESSERACT pattern. |
| 3 | **Engelen, Rimmer & Joosen 2021** — "Troubleshooting CICIDS2017" | IEEE S&P Workshops (WTMC) | **Closest direct analog.** Drops `Destination Port` because it's flow-defining identifier, not behavioral content. Same logic as dropping sourcetype. |
| 4 | **Catillo et al. 2023** — "Faulty use of CIC-IDS 2017" | J. Computer Virology | Quantifies AUC/F1 cost of removing identity features across multiple classifiers. Precedent for ablation table format. |
| 5 | **Apruzzese et al. 2023** — "SoK: Pragmatic Assessment of ML for NIDS" | IEEE EuroS&P | Argues IDS papers should report **deployment-realistic** numbers stripped of dataset artifacts. Provides "headline vs honest" terminology. |
| 6 | **Arce et al. 2025** — "Empirical Quantification of Spurious Correlations in Malware Detection" | arXiv 2506.09662 | Uses integrated gradients to quantify reliance on PE metadata regions. Justifies "strip metadata, report result" framing. |
| 7 | **Kaufman et al. 2012** — "Leakage in Data Mining" | ACM TKDD | Foundational definition of leakage: features carrying target info that shouldn't legitimately be available. |
| 8 | **Sommer & Paxson 2010** — "Outside the Closed World" | IEEE S&P | Counter-argument: domain context (protocol/service) is necessary for interpretable NIDS. Steel-man this in Discussion. |

### 3.2 Recommended thesis framing
Cite **Arp (P4) + Engelen (port-drop precedent) + TESSERACT (honest reporting)** as the three pillars. Position dual-model report as TESSERACT-style honest framework + Engelen-style identity-feature ablation. The 8.7 pp gap is small enough to argue real signal exists.

---

## 4. Specific Field-Drop Justifications (with citation map)

| Dropped column | Leakage type | Citation |
|---|---|---|
| `_time` | Temporal | Kaufman 2012; TESSERACT (temporal bias) |
| `host`, `source` | Identity (collection environment) | Arp P4; TESSERACT (spatial bias) |
| `scenario` | Direct target | Trivial; cite Kaufman for taxonomy |
| `src_ip`, `dest_ip` | IOC memorization | TESSERACT; Engelen 2021 (port analog) |
| `subject_id`, `object_id` | Compound identity | Inherits host+IP leakage |
| `subject_name`, `object_name` | High-cardinality near-unique | Arp P5 (Inappropriate Performance Measures); standard ML practice |
| `logon_id`, `parent_image`, `suricata_alert_signature` | Low permutation importance | Empirical, AutoGluon ablation |
| `sourcetype` (honest variant) | Routing label / spurious correlation | Arp P4; Engelen 2021 (port-drop) |

---

## 5. Unresolved Questions

1. Is sourcetype ever **derived from packet content** in the Splunk pipeline (e.g., `stream:http` inferred from L7 inspection)? If yes, the leakage argument weakens — it becomes a content summary, not pure routing.
2. Worth direct-checking Apruzzese 2023 SoK for explicit "honest vs headline" terminology before citing.
3. Any non-English (Chinese, Korean) papers on BOTSv2? Search was English-only.
4. BOTSv3 ML papers? Brief check found none, but worth deeper search if committee asks "why not the newer dataset."
5. Splunk internal whitepapers with ML metrics on BOTSv2? Splunk ES 8.0 blog hints but gives no numbers.

---

## 6. Sources

- [Arp et al. — Dos and Don'ts of ML in Security (USENIX 2022)](https://www.usenix.org/system/files/sec22summer_arp.pdf)
- [Pendlebury et al. — TESSERACT (USENIX 2019)](https://www.usenix.org/system/files/sec19-pendlebury.pdf)
- [Engelen et al. — Troubleshooting CICIDS2017 (WTMC 2021)](https://intrusion-detection.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf)
- [Catillo et al. — Faulty use of CIC-IDS 2017 (J. Comput. Virol. 2023)](https://link.springer.com/article/10.1007/s11416-023-00509-7)
- [Apruzzese et al. — SoK Pragmatic Assessment NIDS (EuroS&P 2023)](https://arxiv.org/abs/2305.00550)
- [Arce et al. — Spurious Correlations in Malware Detection (arXiv 2025)](https://arxiv.org/abs/2506.09662)
- [Kaufman et al. — Leakage in Data Mining (ACM TKDD 2012)](https://dl.acm.org/doi/10.1145/2382577.2382579)
- [Sommer & Paxson — Outside the Closed World (IEEE S&P 2010)](https://www.icir.org/robin/papers/oakland10-ml.pdf)
- [splunk/botsv2 GitHub](https://github.com/splunk/botsv2)
- [UNSW-NB15 project page](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- [TON_IoT project page](https://research.unsw.edu.au/projects/toniot-datasets)
- [Expectations vs Reality NIDS (arXiv 2403.17458)](https://arxiv.org/html/2403.17458v2)
