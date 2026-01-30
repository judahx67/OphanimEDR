# Intelligent Detection of Non-Essential IoT Traffic on the Home Gateway

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Fabio Palmese, Anna Maria Mandalari, Hamed Haddadi, Alessandro Enrico Cesare Redondi |
| **Year** | 2025 |
| **Published** | 2025-04-22 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2504.18571v1 |
| **Paper URL** | http://arxiv.org/abs/2504.18571v1 |

---

## Citation

```
Fabio Palmese, Anna Maria Mandalari, Hamed Haddadi et al. (2025). "Intelligent Detection of Non-Essential IoT Traffic on the Home Gateway". URL: http://arxiv.org/abs/2504.18571v1
```

---

## Abstract

The rapid expansion of Internet of Things (IoT) devices, particularly in smart home environments, has introduced considerable security and privacy concerns due to their persistent connectivity and interaction with cloud services. Despite advancements in IoT security, effective privacy measures remain uncovered, with existing solutions often relying on cloud-based threat detection that exposes sensitive data or outdated allow-lists that inadequately restrict non-essential network traffic. This work presents ML-IoTrim, a system for detecting and mitigating non-essential IoT traffic (i.e., not influencing the device operations) by analyzing network behavior at the edge, leveraging Machine Learning to classify network destinations. Our approach includes building a labeled dataset based on IoT device behavior and employing a feature-extraction pipeline to enable a binary classification of essential vs. non-essential network destinations. We test our framework in a consumer smart home setup with IoT devices from five categories, demonstrating that the model can accurately identify and block non-essential traffic, including previously unseen destinations, without relying on traditional allow-lists. We implement our solution on a home access point, showing the framework has strong potential for scalable deployment, supporting near-real-time traffic classification in large-scale IoT environments with hundreds of devices. This research advances privacy-aware traffic control in smart ho

---

## Keywords/Categories

cs.CR, cs.LG

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
ent connectivity and interaction with cloud services. Despite advancements in IoT security, effective privacy
measures remain uncovered, with existing solutions often
relying on cloud-based threat detection that exposes sensitive
data or outdated allow-lists that inadequately restrict nonessential network traffic. This work presents ML-IoTrim, a
system for detecting and mitigating non-essential IoT traffic
(i.e., not influencing the device operations) by analyzing
network behavior at the edge, leveraging Machine Learning
to classify network destinations. Our approach includes
building a labeled dataset based on IoT device behavior and
employing a feature-extraction pipeline to enable a binary
classification of essential vs. non-essential network destinations. We test our framework in a consumer smart home
setup with IoT devices from five categories, demonstrating
that the model can accurately identify and block nonessential traffic, including previously unseen destinations,
without relying on traditional allow-lists. We implement our
solution on a home access point, showing the framework has
strong potential for scalable deployment, supporting nearreal-time traffic classification in large-scale IoT environments
with hundreds of devices. This research advances privacyaware traffic control in smart homes, paving the way for
future developments in IoT device privacy.
Index Terms—IoT, IoT Privacy, Network Traffic, ML
1. Introduction
The number of Internet of Things (IoT) devices is
increasing dramatically, revolutionizing our daily lives, especially in the smart home field [1]. However, the presence
of these devices introduces several security and privacy
challenges. In recent years, IoT devices have become
frequent targets or sources of security threats affecting
users and other Internet entities [2]. Given their constant
connectivity and communication with cloud services, IoT
devices pose significant privacy risks, as users are often
unaware of what information is being shared and who
is collecting it. Although many solutions in the literature
effectively counter known security threats, such as through
device protection and isolation (e.g., DDoS detection), privacy concerns remain inadequately addressed [3]. Moreover, most existing solutions are cloud-based, leading to
further exposure of sensitive data during threat detection
processes [3], [4]. Privacy-aware approaches, typically
based on allow-lists, restrict network traffic to only preapproved destinations. However, these methods are often
ineffective, as they depend on predefined lists that are frequently incomplete or outdated, particularly when addressing advertisements or user tracking [5]. The analysis of the
network behavior of consumer smart devices highlights
frequent communication with non-essential destinations,
not contributing to device operations. This work presents
ML-IoTrim, a system designed for the home gateway for
detecting non-essential IoT traffic by inspecting network
chara
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
*Source: arxiv | Paper ID: 3d855944*
