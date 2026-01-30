# Research Gap Analysis: Machine Learning in EDR Systems

**Generated:** 2026-01-29  
**Project:** Ophanim EDR - Thesis Research  
**Focus:** Behavioral Malware Detection using ML on Windows Endpoints

---

## Executive Summary

This analysis identifies key research gaps and opportunities in applying machine learning to Endpoint Detection and Response (EDR) systems. The Ophanim EDR thesis project (Random Forest/Isolation Forest with Sysmon telemetry) can address several under-explored areas while acknowledging the current state-of-the-art.

---

## Table of Contents

1. [Current State of ML in EDR](#1-current-state-of-ml-in-edr)
2. [Identified Research Gaps](#2-identified-research-gaps)
3. [Relevance to Ophanim EDR](#3-relevance-to-ophanim-edr)
4. [Recommended Research Directions](#4-recommended-research-directions)
5. [Key Datasets](#5-key-datasets)
6. [References](#6-references)

---

## 1. Current State of ML in EDR

### 1.1 Dominant Approaches

| Approach | Description | Status |
|----------|-------------|--------|
| **Static Analysis** | PE file features, EMBER-style vectorization | Mature, widely deployed |
| **Dynamic/Behavioral** | Runtime behavior monitoring, API sequences | Growing adoption |
| **Deep Learning** | CNN/LSTM/Transformer for sequence modeling | Research active, limited production |
| **Ensemble Methods** | Random Forest, XGBoost for classification | Production-ready, interpretable |
| **Anomaly Detection** | Isolation Forest, autoencoders for zero-day | Common in EDR products |

### 1.2 Commercial EDR ML Capabilities

Major EDR vendors (CrowdStrike, SentinelOne, Microsoft Defender) incorporate:
- ML-based classification of PE files
- Behavioral anomaly detection
- Process relationship analysis
- Memory scanning with ML assist

However, **proprietary implementations create knowledge gaps** for academic research.

---

## 2. Identified Research Gaps

### 2.1 🔴 Gap 1: Lab vs. Real-World Performance Discrepancy

> **Problem:** ML models show 90%+ accuracy in sandbox environments but 20-50% in real endpoints.

**Current Limitations:**
- Sandbox features differ from live endpoint telemetry
- Malware employs sandbox evasion techniques
- Feature extraction assumes controlled execution

**Research Opportunity:**
- Develop models trained on **live endpoint telemetry** (not sandbox)
- Study feature drift between lab and production
- Create evaluation frameworks for real-world performance

**Ophanim Relevance:** ⭐⭐⭐⭐⭐  
*Ophanim collects live Windows telemetry via Sysmon, directly addressing this gap by training on real endpoint data rather than sandbox features.*

---

### 2.2 🔴 Gap 2: Limited Sysmon-based ML Research

> **Problem:** Most ML research uses static PE features (EMBER) rather than runtime Sysmon events.

**Current State:**
- EMBER dataset: Static PE features (widely used)
- BETH dataset: Kernel-level process calls + network (limited adoption)
- Sysmon-specific ML pipelines: **Under-researched**

**Research Opportunity:**
- Feature engineering from Sysmon Event IDs (1, 3, 11, 12, 13, etc.)
- Temporal modeling of process creation sequences
- Parent-child process relationship features

**Ophanim Relevance:** ⭐⭐⭐⭐⭐  
*Ophanim's Sysmon collector provides exactly this data. Developing ML features from Sysmon events is a direct thesis contribution.*

---

### 2.3 🟡 Gap 3: Explainability (XAI) in EDR Detections

> **Problem:** ML models are "black boxes" - analysts cannot understand why threats were detected.

**Current Limitations:**
- Deep learning models lack transparency
- Alert fatigue worsens without explanation
- Incident response requires understanding attack chains

**Research Opportunity:**
- SHAP/LIME analysis for Random Forest detections
- Feature importance visualization for analysts
- Attack narrative generation from ML outputs

**Ophanim Relevance:** ⭐⭐⭐⭐  
*Random Forest inherently provides feature importance. Thesis can include XAI dashboard component.*

---

### 2.4 🟡 Gap 4: Adversarial Robustness

> **Problem:** ML-based EDR can be bypassed by adversarial manipulation.

**Attack Vectors:**
- Feature space manipulation (process name spoofing)
- Timing attacks to evade behavioral windows
- Model extraction and evasion

**Research Opportunity:**
- Adversarial training for robustness
- Ensemble diversity to prevent single-point evasion
- Red team evaluation of ML detectors

**Ophanim Relevance:** ⭐⭐⭐  
*Future work: Evaluate Ophanim against adversarial samples. Out of core thesis scope but valuable.*

---

### 2.5 🟡 Gap 5: Real-Time Latency Constraints

> **Problem:** Deep learning models are computationally expensive for endpoint deployment.

**Trade-offs:**
| Model Type | Accuracy | Latency | Endpoint-Suitable |
|------------|----------|---------|-------------------|
| Random Forest | Good | Low ✅ | Yes |
| XGBoost | Good | Low ✅ | Yes |
| LSTM | Better | Medium | Maybe |
| Transformer | Best | High ❌ | No (cloud only) |

**Research Opportunity:**
- Model distillation for edge deployment
- Hybrid architectures (lightweight + cloud)
- Streaming ML for continuous inference

**Ophanim Relevance:** ⭐⭐⭐⭐  
*Random Forest + Isolation Forest chosen specifically for low-latency endpoint inference. Thesis validates this design choice.*

---

### 2.6 🟢 Gap 6: Dataset Scarcity for Behavioral Analysis

> **Problem:** Lack of labeled behavioral datasets for Windows endpoint security.

**Available Datasets:**

| Dataset | Type | Events | Labeled | Year |
|---------|------|--------|---------|------|
| **EMBER** | Static PE | 1.1M | ✅ | 2018 |
| **EMBER2018** | Static PE | 1M | ✅ | 2018 |
| **BETH** | Behavioral (honeypot) | 8M+ | ✅ | 2021 |
| **LANL** | Auth/network logs | 1B+ | ✅ | 2015 |
| Custom Sysmon | Behavioral | - | ❌ | - |

**Research Opportunity:**
- Build labeled Sysmon dataset from controlled malware execution
- Contribute open behavioral dataset to research community
- Study concept drift in behavioral features

**Ophanim Relevance:** ⭐⭐⭐⭐⭐  
*Thesis can contribute a labeled Sysmon behavioral dataset. Even a small dataset for thesis validation is novel.*

---

### 2.7 🟢 Gap 7: Sequential/Temporal Modeling of Process Behavior

> **Problem:** Traditional ML treats events independently; ignores temporal patterns.

**Underexplored:**
- Process lifecycle modeling (create → modify → network → terminate)
- Attack chain detection via sequence analysis
- Time-windowed feature aggregation

**Deep Learning Approaches (Limited Production Use):**
- LSTM for API call sequences
- Transformer for process graph embeddings
- GNN for process relationship modeling

**Ophanim Relevance:** ⭐⭐⭐  
*Phase 1: Window-based aggregation. Future: Sequence modeling as thesis extension.*

---

### 2.8 🟢 Gap 8: Fileless Malware Detection

> **Problem:** Fileless malware operates in memory, evading static analysis.

**Detection Challenges:**
- No PE file to analyze statically
- PowerShell/WMI/Office macro execution
- Living-off-the-land techniques (LOLBins)

**Research Opportunity:**
- Command-line argument analysis with NLP
- Script content hashing and classification
- Parent process anomaly detection for LOLBins

**Ophanim Relevance:** ⭐⭐⭐  
*Sysmon Event ID 1 includes command-line. Thesis can include PowerShell/LOLBin detection features.*

---

## 3. Relevance to Ophanim EDR

### 3.1 Thesis Alignment Matrix

| Gap | Ophanim Addresses | Thesis Contribution |
|-----|-------------------|---------------------|
| Lab vs. Real-World | ✅ Live telemetry | Direct contribution |
| Sysmon ML Pipeline | ✅ Core design | Direct contribution |
| XAI/Explainability | ⚡ Random Forest | Feature importance dashboard |
| Adversarial Robustness | ❌ Future work | Out of scope |
| Real-Time Latency | ✅ RF/IF choice | Validates lightweight approach |
| Dataset Scarcity | ⚡ Potential | Create small labeled set |
| Sequential Modeling | ⚡ Time windows | Basic; future work |
| Fileless Malware | ⚡ Command-line | Include in features |

### 3.2 Unique Contribution Statement

> **Ophanim EDR contributes to the field by:**
> 
> 1. Demonstrating an **end-to-end ML pipeline from live Sysmon telemetry** (not sandbox features)
> 2. Providing a **practical, low-latency detection system** suitable for thesis-scale deployment
> 3. Offering an **open-source, documented architecture** for academic reproducibility
> 4. Combining **Random Forest (classification) + Isolation Forest (anomaly)** for multi-layered detection

---

## 4. Recommended Research Directions

### 4.1 Primary (Thesis Scope)

1. **Sysmon Feature Engineering**
   - Design features from Event IDs 1, 3, 11, 12, 13
   - Process tree depth, command-line length/entropy
   - Network connection patterns per process

2. **Multi-Endpoint Evaluation**
   - Deploy on 2-4 Windows VMs
   - Collect baseline benign data
   - Execute controlled malware samples

3. **Detection Performance Study**
   - Compare RF vs. IF performance
   - Measure precision/recall on malware samples
   - Document false positive rates

### 4.2 Secondary (Thesis Extensions)

1. **Explainability Dashboard**
   - SHAP analysis for detections
   - Feature contribution visualization

2. **Small Behavioral Dataset**
   - Labeled Sysmon events from controlled experiments
   - Contribute to research community

### 4.3 Future Work (Post-Thesis)

1. **LSTM/Transformer Integration**
   - Sequence modeling for attack chains
   - Server-side deep learning

2. **Adversarial Evaluation**
   - Test against evasion techniques
   - Red team validation

---

## 5. Key Datasets

### 5.1 For Training/Benchmarking

| Dataset | Use Case | URL |
|---------|----------|-----|
| **EMBER** | Static PE classification | [GitHub](https://github.com/elastic/ember) |
| **BETH** | Behavioral anomaly detection | [Kaggle](https://www.kaggle.com/datasets/katehighnam/beth-dataset) |
| **LANL** | Auth/lateral movement | [LANL](https://csr.lanl.gov/data/cyber1/) |

### 5.2 For Feature Engineering Reference

| Paper/Resource | Focus |
|----------------|-------|
| EMBER Paper | PE feature extraction methodology |
| BETH Paper | Kernel-level feature design |
| Sysmon Config Examples | Event taxonomy |

---

## 6. References

### Academic Sources

1. Anderson, H. S., & Roth, P. (2018). EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. *arXiv preprint arXiv:1804.04637*.

2. Highnam, K., et al. (2021). BETH Dataset for Anomaly Detection Research. *NeurIPS Workshops*.

3. Various arXiv papers on ML-based malware detection (2023-2025).

### Industry Sources

1. CrowdStrike, SentinelOne - Commercial EDR architectures
2. Microsoft Sysmon documentation
3. MITRE ATT&CK framework

---

## Conclusion

The Ophanim EDR thesis project addresses **real research gaps** in the field, particularly:

1. **Gap 1 (Lab vs. Real-World):** By using live Sysmon telemetry
2. **Gap 2 (Sysmon ML):** By building an ML pipeline on Sysmon events
3. **Gap 5 (Latency):** By choosing Random Forest/Isolation Forest

The project is positioned to make a **meaningful academic contribution** while remaining achievable within thesis scope.

---

*Generated by Research Gap Analysis Tool - Ophanim EDR Project*
