# Interpretable Anomaly Detection in Encrypted Traffic Using SHAP with Machine Learning Models

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Kalindi Singh, Aayush Kashyap, Aswani Kumar Cherukuri |
| **Year** | 2025 |
| **Published** | 2025-05-22 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2505.16261v1 |
| **Paper URL** | http://arxiv.org/abs/2505.16261v1 |

---

## Citation

```
Kalindi Singh, Aayush Kashyap, Aswani Kumar Cherukuri (2025). "Interpretable Anomaly Detection in Encrypted Traffic Using SHAP with Machine Learning Models". URL: http://arxiv.org/abs/2505.16261v1
```

---

## Abstract

Purpose: The widespread adoption of encrypted communication protocols such as HTTPS and TLS has enhanced data privacy but also rendered traditional anomaly detection techniques less effective, as they often rely on inspecting unencrypted payloads. This study aims to develop an interpretable machine learning-based framework for anomaly detection in encrypted network traffic. Design/methodology/approach: This study proposes a model-agnostic framework that integrates multiple machine learning classifiers — XGBoost, Random Forest, and Isolation Forest — with SHapley Additive exPlanations (SHAP) to ensure post-hoc model interpretability. The models are trained and evaluated on three benchmark encrypted traffic datasets: CIC-Darknet2020, USTC-TFC2016, and CSE-CIC-IDS2018. Performance is assessed using standard classification metrics, and SHAP is used to explain model predictions by attributing importance to individual input features. Findings: The XGBoost model achieved a peak classification accuracy of 99.94%, outperforming other models across multiple datasets. SHAP visualizations successfully revealed the most influential traffic features contributing to anomaly predictions, enhancing the transparency and trustworthiness of the models. Originality: Unlike conventional approaches that treat machine learning as a black box, this work combines robust classification techniques with explainability through SHAP, offering a novel interpretable anomaly detection system tailored for encrypted traffic environments. Research Limitations & Implications: This study is limited to three publicly available encrypted traffic datasets. While the framework is generalizable, real-time deployment and performance under adversarial conditions require --- Page 2 --- 2 further investigation. Future work may explore adaptive models and real-time interpretability in operational network environments. Practical implications: This interpretable anomaly detection framework can be integrated into modern security operations for encrypted environments, allowing analysts not only to detect anomalies with high precision but also to understand why a model made a particular decision — a crucial capability in compliance-driven and mission-critical settings.

---

## Keywords/Categories

cs.CR

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
ss
effective, as they often rely on inspecting unencrypted payloads. This study aims to develop an
interpretable machine learning-based framework for anomaly detection in encrypted network
traffic.
Design/methodology/approach:
This study proposes a model-agnostic framework that integrates multiple machine learning
classifiers — XGBoost, Random Forest, and Isolation Forest — with SHapley Additive
exPlanations (SHAP) to ensure post-hoc model interpretability. The models are trained and
evaluated on three benchmark encrypted traffic datasets: CIC-Darknet2020, USTC-TFC2016,
and CSE-CIC-IDS2018. Performance is assessed using standard classification metrics, and
SHAP is used to explain model predictions by attributing importance to individual input
features.
Findings:
The XGBoost model achieved a peak classification accuracy of 99.94%, outperforming other
models across multiple datasets. SHAP visualizations successfully revealed the most
influential traffic features contributing to anomaly predictions, enhancing the transparency and
trustworthiness of the models.
Originality:
Unlike conventional approaches that treat machine learning as a black box, this work combines
robust classification techniques with explainability through SHAP, offering a novel
interpretable anomaly detection system tailored for encrypted traffic environments.
Research Limitations & Implications:
This study is limited to three publicly available encrypted traffic datasets. While the framework
is generalizable, real-time deployment and performance under adversarial conditions require

--- Page 2 ---

2

further investigation. Future work may explore adaptive models and real-time interpretability
in operational network environments.
Practical implications:
This interpretable anomaly detection framework can be integrated into modern security
operations for encrypted environments, allowing analysts not only to detect anomalies with
high precision but also to understand why a model made a particular decision — a crucial
capability in compliance-driven and mission-critical settings.
Keywords: anomaly detection, network traffic security, explainable artificial intelligence.
1. Introduction
The exponential growth of encrypted network traffic, driven by the widespread adoption of
protocols like HTTPS, TLS, and VPN tunnelling, has significantly bolstered data
confidentiality and user privacy across the internet. A network attack is where an attacker gains
unauthorised access to the network to perform malicious activities [4]. As organizations
increasingly rely on encrypted channels to safeguard sensitive information, these protocols
have become the default for secure communications. However, this surge in encryption has
posed a unique set of challenges for cybersecurity analysts and network administrators.
Traditional anomaly detection systems, which rely heavily on deep packet inspection (DPI)
and payload analysis, struggle to operate effectively in encrypted environments, as they are
una
```

---

## Relevance to EDR/Malware Detection

*[To be filled in during literature review]*

- **Key Contribution:** 
- **Methods Used:** 
- **Datasets:** 
- **Results:** 
- **Limitations:** 

---

## Notes

*[Add your notes here]*

---

*Note generated: 2026-01-30 01:18*
*Source: arxiv | Paper ID: f2eea5d7*
