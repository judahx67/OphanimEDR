# Literature Synthesis: Machine Learning in EDR and Behavioral Analysis

**Generated:** 2026-01-30  
**Papers Reviewed:** 24 (arXiv, 2023-2025)  
**Focus:** Endpoint Detection, Anomaly Detection, Behavioral Analysis, Network Traffic

---

## Executive Summary

This synthesis analyzes 24 recent papers (2023-2025) on machine learning applications in endpoint security, intrusion detection, and behavioral anomaly analysis. Key themes include:

1. **AutoML-based IDS** - Automated feature selection and model optimization
2. **Behavior-level detection** - Multi-flow analysis beyond single-packet inspection
3. **Deep learning architectures** - CNN-BiLSTM, GNN, Autoencoders for traffic analysis
4. **Explainability (XAI)** - SHAP-based interpretable anomaly detection
5. **Streaming/online learning** - Handling concept drift in real-time systems

---

## Key Papers by Theme

### 🔴 Most Relevant: Endpoint Detection & Response

| Paper | Year | Key Contribution |
|-------|------|------------------|
| **Endpoint Security Agent** | 2025 | Real-time Windows monitoring via WMI/ETW with ML detection mapped to MITRE ATT&CK |
| **Are we there yet? P-EDR** | 2023 | Industry viewpoint on Provenance-based EDR - identifies gaps between academia/industry |

**Key Findings:**
- P-EDR systems are more effective than conventional EDR but face operating cost concerns
- Three gaps: (1) client-side overhead neglected, (2) imbalanced alarm costs, (3) server memory issues
- Endpoint agents using WMI/ETW + ML achieve high accuracy with MITRE ATT&CK mapping

---

### 🟡 Behavioral & Network Traffic Analysis

| Paper | Year | Method | Dataset | F1 Score |
|-------|------|--------|---------|----------|
| **BLADE** | 2025 | Autoencoder + One-class classifier | CIC-IDS2017 | 0.9801 |
| **CNN-BiLSTM** | 2025 | CNN + BiGRU | NF-BoT-IoT | 0.99 |
| **CST-AFNet** | 2025 | Dual attention CNN + BiGRU | Edge-IIoTset | 0.997 |
| **Semi-Supervised via Normalizing Flows** | 2024 | Bidirectional flows | Various | SOTA |
| **GNN Anomaly Detection** | 2024 | Graph Neural Networks | Network flows | Novel |

**Key Observations:**
- BLADE introduces **behavior-level detection** using multi-flow analysis
- CNN-BiLSTM combinations achieve 99%+ accuracy on standard benchmarks
- Unsupervised methods can generate pseudo-anomalies without labeled attack data

---

### 🟢 AutoML & Automated IDS

| Paper | Year | Approach |
|-------|------|----------|
| **Autonomous Cybersecurity: AutoML Framework** | 2024 | TVAE data balancing + BO hyperparameter tuning + OCSE ensemble |
| **Multi-Objective AutoML IDS** | 2025 | OIP-AutoFS feature selection + OPCE-CASH model optimization |

**Innovation:** Integrates all four AutoML stages with multi-objective optimization for detection effectiveness, efficiency, and confidence suitable for resource-constrained IoT.

---

### 🟣 Explainability & Interpretability

| Paper | Year | XAI Method |
|-------|------|------------|
| **Interpretable Anomaly Detection in Encrypted Traffic** | 2025 | SHAP |
| **Improving Network Threat Detection with KG + LLM** | 2025 | Knowledge Graph + LLM interpretation |

**Key Point:** SHAP provides feature importance for ML predictions in encrypted traffic, enabling transparent threat detection.

---

### 🔵 Online & Streaming Learning

| Paper | Year | Approach | Result |
|-------|------|----------|--------|
| **Online Self-Supervised Deep Learning for IDS** | 2023 | Random Neural Network | Fully online, no offline training |
| **Binary Anomaly Detection under Concept Drift** | 2025 | Adaptive Random Forest | F1=0.990, 1/3 compute cost |
| **Meta-UAD** | 2024 | Meta-learning K-shot | 15-43% F1 improvement |

**Critical Finding:** Adaptive Random Forest handles concept drift effectively, achieving F1=0.990 with only 1/3 computational cost of batch models.

---

## Datasets Used Across Papers

| Dataset | Type | Size | Use Cases |
|---------|------|------|-----------|
| **CIC-IDS2017** | Network intrusion | 2.8M flows | Baseline benchmark |
| **NSL-KDD** | Network intrusion | 150K | Traditional IDS evaluation |
| **NF-BoT-IoT** | IoT botnet | - | IoT-specific detection |
| **Edge-IIoTset** | Industrial IoT | 2.2M | 15 attack types |
| **5G-NIDD** | 5G network | - | Mobile network IDS |

---

## ML Techniques Summary

### Classification Models
- **Decision Tree / Random Forest** - Fast, interpretable, production-ready
- **SVM** - Second-layer classification in dual-layer systems
- **XGBoost** - Strong baseline in AutoML pipelines

### Deep Learning
- **CNN** - Spatial feature extraction from traffic
- **BiLSTM / BiGRU** - Temporal sequence modeling
- **Autoencoders** - Unsupervised anomaly detection via reconstruction error
- **GNN** - Relationship modeling in network graphs
- **Transformers** - Limited adoption due to computational cost

### Unsupervised Methods
- **Isolation Forest** - One-class anomaly detection
- **Normalizing Flows** - Generating pseudo-anomalies
- **Clustering** - Pseudo-labeling in BLADE

---

## Research Gaps Identified

1. **Real-world vs. Lab Performance**
   - Models achieve 99% in benchmarks but ~82% in real deployment
   - Need for live endpoint telemetry training

2. **Sysmon-based Pipelines**
   - Most research uses network flows, not Windows Sysmon events
   - Windows endpoint behavioral ML remains under-explored

3. **Explainability**
   - Black-box models insufficient for SOC analysts
   - SHAP integration showing promise

4. **Concept Drift**
   - Traditional batch models fail as attacks evolve
   - Streaming/online learning emerging as solution

5. **Resource Constraints**
   - IoT/endpoint devices lack compute for deep learning
   - Random Forest/Isolation Forest preferred for edge

---

## Relevance to Ophanim EDR

| Research Finding | Ophanim Application |
|------------------|---------------------|
| WMI/ETW monitoring + ML | Already implemented in agent collectors |
| Random Forest + MITRE mapping | Direct alignment with thesis design |
| Adaptive RF for streaming | Consider for future real-time detection |
| SHAP explainability | Add feature importance to dashboard |
| Sysmon-based detection gap | Unique thesis contribution |

---

## Recommended Reading Priority

### High Priority (Directly Relevant)
1. `72ba23d6_Endpoint_Security_Agent_*.md` - Windows EDR with ML
2. `fb224763_Are_we_there_yet_*.md` - Industry perspective on P-EDR
3. `772cd0be_BLADE_*.md` - Behavior-level anomaly detection
4. `acbc8a08_Binary_Anomaly_Detection_*.md` - Adaptive RF for streaming

### Medium Priority (Good Techniques)
5. `3fcd055f_Towards_Autonomous_Cybersecurity_*.md` - AutoML IDS
6. `a2e1dcbf_Toward_Autonomous_and_Efficient_*.md` - Multi-objective AutoML
7. `f2eea5d7_Interpretable_Anomaly_Detection_*.md` - SHAP for encrypted traffic
8. `efd5168c_Online_Self-Supervised_*.md` - Online learning IDS

### Lower Priority (Specialized Topics)
- CNN-BiLSTM models (3d531630, a84fce93)
- IoT-specific papers (3d855944, cb185be7)
- Privacy-focused papers (4b9afa41, 57e3c598)

---

## Citations

All papers are from arXiv (cs.CR, cs.LG categories), 2023-2025. Full citations available in individual note files under `notes/`.

---

*Synthesis generated from autonomous research crawl on 2026-01-30*
