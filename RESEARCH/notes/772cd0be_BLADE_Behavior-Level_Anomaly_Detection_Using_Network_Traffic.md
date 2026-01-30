# BLADE: Behavior-Level Anomaly Detection Using Network Traffic in Web Services

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Zhibo Dong, Yong Huang, Shubao Sun, Wentao Cui, Zhihua Wang |
| **Year** | 2025 |
| **Published** | 2025-11-07 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2511.05193v1 |
| **Paper URL** | http://arxiv.org/abs/2511.05193v1 |

---

## Citation

```
Zhibo Dong, Yong Huang, Shubao Sun et al. (2025). "BLADE: Behavior-Level Anomaly Detection Using Network Traffic in Web Services". URL: http://arxiv.org/abs/2511.05193v1
```

---

## Abstract

With their widespread popularity, web services have become the main targets of various cyberattacks. Existing traffic anomaly detection approaches focus on flow-level attacks, yet fail to recognize behavior-level attacks, which appear benign in individual flows but reveal malicious purpose using multiple network flows. To transcend this limitation, we propose a novel unsupervised traffic anomaly detection system, BLADE, capable of detecting not only flow-level but also behavior-level attacks in web services. Our key observation is that application-layer operations of web services exhibit distinctive communication patterns at the network layer from a multi-flow perspective. BLADE first exploits a flow autoencoder to learn a latent feature representation and calculates its reconstruction losses per flow. Then, the latent representation is assigned a pseudo operation label using an unsupervised clustering method. Next, an anomaly score is computed based on the reconstruction losses. Finally, the triplets of timestamps, pseudo labels, and anomaly scores from multiple flows are aggregated and fed into a one-class classifier to characterize the behavior patterns of legitimate web operations, enabling the detection of flow-level and behavior-level anomalies. BLADE is extensively evaluated on both the custom dataset and the CIC-IDS2017 dataset. The experimental results demonstrate BLADE's superior performance, achieving high F1 scores of 0.9732 and 0.9801, respectively, on the two da

---

## Keywords/Categories

cs.CR

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
on flow-level attacks, yet
fail to recognize behavior-level attacks, which appear benign
in individual flows but reveal malicious purpose using multiple
network flows. To transcend this limitation, we propose a novel
unsupervised traffic anomaly detection system, BLADE, capable
of detecting not only flow-level but also behavior-level attacks
in web services. Our key observation is that application-layer
operations of web services exhibit distinctive communication
patterns at the network layer from a multi-flow perspective.
BLADE first exploits a flow autoencoder to learn a latent feature
representation and calculates its reconstruction losses per flow.
Then, the latent representation is assigned a pseudo operation
label using an unsupervised clustering method. Next, an anomaly
score is computed based on the reconstruction losses. Finally,
the triplets of timestamps, pseudo labels, and anomaly scores
from multiple flows are aggregated and fed into a one-class
classifier to characterize the behavior patterns of legitimate web
operations, enabling the detection of flow-level and behavior-level
anomalies. BLADE is extensively evaluated on both the custom
dataset and the CIC-IDS2017 dataset. The experimental results
demonstrate BLADE’s superior performance, achieving high F1
scores of 0.9732 and 0.9801, respectively, on the two datasets,
and outperforming traditional single-flow anomaly detection
baselines.
Index Terms—traffic anomaly detection, multi-flow analysis,
unsupervised learning, behavioral patterns, web service security.
I. INTRODUCTION
Web services play a pivotal role in today’s digital landscape
and enable seamless communication and data exchange between different applications and systems. With their increasing
prevalence, web services have become prime targets for a
wide range of cyberattacks. It is reported that in 2024, attacks
on web services have surpassed 311 billion and resulted in
approximately 87 billion dollars in global losses [1]. Malicious
traffic analysis is a critical component in safeguarding web
services, enabling timely threat detection and mitigation [2],
[3]. Since malicious traffic represents a negligible share of the
total network traffic and is evolving at a rapid pace, a popular
strategy is to design malicious traffic analysis as an anomaly
detection task [4]–[6].
Despite growing attempts and extensive endeavors, existing
traffic anomaly detection approaches focus on verifying a
single network flow and limit themselves to flow-level attacks
*The corresponding author is Yong Huang (yonghuang@zzu.edu.cn).
such as injection, scanning, and brute-force attacks [7]–[11].
These attacks are often triggered by malicious payloads or
abnormal communication patterns observable within a single
network flow. However, these approaches struggle to detect
behavior-level attacks, which rarely reveal malicious intent
within a single flow and instead exploit vulnerabilities of
application-layer rules and configurations through multiple
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
*Source: arxiv | Paper ID: 772cd0be*
