# GNN-based Anomaly Detection for Encoded Network Traffic

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Anasuya Chattopadhyay, Daniel Reti, Hans D. Schotten |
| **Year** | 2024 |
| **Published** | 2024-05-22 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2405.13670v1 |
| **Paper URL** | http://arxiv.org/abs/2405.13670v1 |

---

## Citation

```
Anasuya Chattopadhyay, Daniel Reti, Hans D. Schotten (2024). "GNN-based Anomaly Detection for Encoded Network Traffic". URL: http://arxiv.org/abs/2405.13670v1
```

---

## Abstract

The early research report explores the possibility of using Graph Neural Networks (GNNs) for anomaly detection in internet traﬃc data enriched with information. While recent studies have made signiﬁcant progress in using GNNs for anomaly detection in ﬁnance, multivariate time-series, and biochemistry domains, there is limited research in the context of network ﬂow data. In this report, we explore the idea that leverages information-enriched features extracted from network ﬂow packet data to improve the performance of GNN in anomaly detection. The idea is to utilize feature encoding (binary, numerical, and string) to capture the relationships between the network components, allowing the GNN to learn latent relationships and better identify anomalies. CCS CONCEPTS • Security and privacy →Intrusion detection systems.

---

## Keywords/Categories

cs.SI, cs.CR, cs.LG

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
Research Center for
Artiﬁcial Intelligence
Kaiserslautern, Germany
ABSTRACT
The early research report explores the possibility of using Graph
Neural Networks (GNNs) for anomaly detection in internet traﬃc
data enriched with information. While recent studies have made
signiﬁcant progress in using GNNs for anomaly detection in ﬁnance, multivariate time-series, and biochemistry domains, there
is limited research in the context of network ﬂow data. In this report, we explore the idea that leverages information-enriched features extracted from network ﬂow packet data to improve the performance of GNN in anomaly detection. The idea is to utilize feature encoding (binary, numerical, and string) to capture the relationships between the network components, allowing the GNN to
learn latent relationships and better identify anomalies.
CCS CONCEPTS
• Security and privacy →Intrusion detection systems.
KEYWORDS
Graph Neural Networks, Network Security, Anomaly Detection,
Feature Encoding, Internet Traﬃc, Cyber Security
ACM Reference Format:
Anasuya Chattopadhyay, Daniel Reti, and Hans D. Schotten. 2023. GNNbased Anomaly Detection for Encoded Network Traﬃc. In Proceedings of
ACM on Networking (PACMNET) (CoNEXT-SW ’23). ACM, New York, NY,
USA, 2 pages. https://doi.org/XXXXXXX.XXXXXXX
1
INTRODUCTION
Anomaly detection plays a critical role in cybersecurity, where
identifying unusual or malicious activities on the internet is of
paramount importance. Traditional anomaly detection methods often rely on predeﬁned rules and heuristics, making them less adaptable to ever-evolving threats. Graph Neural Networks (GNNs) oﬀer
a promising avenue for improving the detection of such threats by
capturing complex relationships and patterns in network data. A
typical GNN architecture consists of multiple layers, each updating
node representations based on their neighbors’ information. The
Permission to make digital or hard copies of all or part of this work for personal or
classroom use is granted without fee provided that copies are not made or distributed
for proﬁt or commercial advantage and that copies bear this notice and the full citation on the ﬁrst page. Copyrights for components of this work owned by others than
ACM must be honored. Abstracting with credit is permitted. To copy otherwise, or republish, to post on servers or to redistribute to lists, requires prior speciﬁc permission
and/or a fee. Request permissions from permissions@acm.org.
CoNEXT-SW ’23, December 8, 2023, Paris, France
© 2023 Association for Computing Machinery.
ACM ISBN 978-1-4503-XXXX-X/23/12...$15.00
https://doi.org/XXXXXXX.XXXXXXX
ﬁnal node embeddings are then used for anomaly detection. Posttraining, GNNs can be deployed for real-time anomaly detection
by analyzing the incoming traﬃc data and ﬂagging instances that
deviate from learned patterns as potential anomalies.
Recent research in anomaly detection has predominantly focused
on domains like image [5], ﬁnance [7], Internet of Things (IoT) [3,

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
*Source: arxiv | Paper ID: de0dc264*
