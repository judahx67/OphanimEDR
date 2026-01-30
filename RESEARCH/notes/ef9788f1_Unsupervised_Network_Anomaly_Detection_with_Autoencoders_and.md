# Unsupervised Network Anomaly Detection with Autoencoders and Traffic Images

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Michael Neri, Sara Baldoni |
| **Year** | 2025 |
| **Published** | 2025-05-22 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2505.16650v1 |
| **Paper URL** | http://arxiv.org/abs/2505.16650v1 |

---

## Citation

```
Michael Neri, Sara Baldoni (2025). "Unsupervised Network Anomaly Detection with Autoencoders and Traffic Images". DOI: 10.23919/EUSIPCO63237.2025.11226720. URL: http://arxiv.org/abs/2505.16650v1
```

---

## Abstract

Due to the recent increase in the number of connected devices, the need to promptly detect security issues is emerging. Moreover, the high number of communication flows creates the necessity of processing huge amounts of data. Furthermore, the connected devices are heterogeneous in nature, having different computational capacities. For this reason, in this work we propose an image-based representation of network traffic which allows to realize a compact summary of the current network conditions with 1-second time windows. The proposed representation highlights the presence of anomalies thus reducing the need for complex processing architectures. Finally, we present an unsupervised learning approach which effectively detects the presence of anomalies. The code and the dataset are available at https://github.com/michaelneri/image-based-network-traffic-anomaly-detection.

---

## Keywords/Categories

cs.CV, cs.CR, eess.IV, eess.SP

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
ates the necessity of processing huge amounts of data.
Furthermore, the connected devices are heterogeneous in nature,
having different computational capacities. For this reason, in
this work we propose an image-based representation of network traffic which allows to realize a compact summary of
the current network conditions with 1-second time windows.
The proposed representation highlights the presence of anomalies thus reducing the need for complex processing architectures. Finally, we present an unsupervised learning approach
which effectively detects the presence of anomalies. The code
and the dataset are available at https://github.com/michaelneri/
image-based-network-traffic-anomaly-detection.
Index Terms—Unsupervised anomaly detection, Image-based
network representation, Autoencoder.
I. INTRODUCTION
The current diffusion of Internet-related technologies is
leading to an unprecedented connectivity among heterogeneous devices with varied computational capabilities. The
extensive use of computer networks creates security risks that
can lead to misconduct and substantial harm. These threats
are dynamic and prone to evolve into unknown forms [1]. To
properly react to this danger, a prompt detection of anomalous
network behaviors is needed. An anomalous event can be
defined as a network pattern that diverges from the expected
normal behavior [2]. The design of anomaly detection techniques is challenging for several reasons. First, the wide
diffusion of connected devices causes a relevant increase in
the number of traffic flows, making the real-time detection of
anomalies a demanding task. Moreover, due to the inherent
disparity between the amount of normal and anomalous data
flows, the adoption of supervised learning methods is hindered.
Furthermore, these techniques often fail in accurately identifying unfamiliar abnormal behaviors [3], [4]. Consequently, the
exploration of unsupervised learning techniques has emerged
as a prominent direction for addressing anomaly detection
within telecommunication networks. In the context of unsupervised techniques, a key task consists in modeling the normal
state of a telecommunication network. To this end, different
types of predictors such as traffic usage, protocols, and number
The research presented in this paper was partially funded by the project
“ISEEYOO: AI-based Network Anomaly Detection for CPS exploiting 2D
data representation” within the University of Padova funding framework
“SEED research grants.”
of flows can be employed [4], [5]. Due to the high number
of predictors, dimensionality reduction techniques, such as
Principal Component Analysis (PCA) [6], have been employed
for analyzing network traffic [7]–[9]. Recently, deep learning
in anomaly detection has represented an important shift from
traditional PCA-based methods. Deep learning approaches
can capture non-linear relationships and high-level abstractions, offering enhanced detection capabilities in diverse and
complex scenarios [11]. Ho
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
*Source: arxiv | Paper ID: ef9788f1*
