# Semi-Supervised Learning for Anomaly Traffic Detection via Bidirectional Normalizing Flows

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Zhangxuan Dang, Yu Zheng, Xinglin Lin, Chunlei Peng, Qiuyu Chen |
| **Year** | 2024 |
| **Published** | 2024-03-13 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2403.10550v1 |
| **Paper URL** | http://arxiv.org/abs/2403.10550v1 |

---

## Citation

```
Zhangxuan Dang, Yu Zheng, Xinglin Lin et al. (2024). "Semi-Supervised Learning for Anomaly Traffic Detection via Bidirectional Normalizing Flows". URL: http://arxiv.org/abs/2403.10550v1
```

---

## Abstract

With the rapid development of the Internet, various types of anomaly trafﬁc are threatening network security. We consider the problem of anomaly network trafﬁc detection and propose a threestage anomaly detection framework using only normal trafﬁc. Our framework can generate pseudo anomaly samples without prior knowledge of anomalies to achieve the detection of anomaly data. Firstly, we employ a reconstruction method to learn the deep representation of normal samples. Secondly, these representations are normalized to a standard normal distribution using a bidirectional ﬂow module. To simulate anomaly samples, we add noises to the normalized representations which are then passed through the generation direction of the bidirectional ﬂow module. Finally, a simple classiﬁer is trained to differentiate the normal samples and pseudo anomaly samples in the latent space. During inference, our framework requires only two modules to detect anomalous samples, leading to a considerable reduction in model size. According to the experiments, our method achieves the state of-the-art results on the common benchmarking datasets of anomaly network trafﬁc detection. The code is given in the https://github.com/ZxuanDang/ATD-via-Flows.git 1

---

## Keywords/Categories

cs.LG, cs.AI, cs.CR

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
threestage anomaly detection framework using only normal trafﬁc. Our framework can generate pseudo
anomaly samples without prior knowledge of anomalies to achieve the detection of anomaly data.
Firstly, we employ a reconstruction method to learn the deep representation of normal samples.
Secondly, these representations are normalized to a standard normal distribution using a bidirectional ﬂow module. To simulate anomaly samples, we add noises to the normalized representations
which are then passed through the generation direction of the bidirectional ﬂow module. Finally, a
simple classiﬁer is trained to differentiate the normal samples and pseudo anomaly samples in the
latent space. During inference, our framework requires only two modules to detect anomalous samples, leading to a considerable reduction in model size. According to the experiments, our method
achieves the state of-the-art results on the common benchmarking datasets of anomaly network
trafﬁc detection. The code is given in the https://github.com/ZxuanDang/ATD-via-Flows.git
1
Introduction
With the development of the Internet, the proliferation of devices has led to explosive growth in the
Internet trafﬁc, which poses signiﬁcant challenges to
the management of network resources and the assurance of network security. In particular, the increasing
complexity and diversity of network attacks require
systems to enhance their ability to detect anomaly
trafﬁc.
Anomaly network trafﬁc detection is a vital component in ensuring network security by detecting anomaly trafﬁc passing through computer network nodes. Such network trafﬁc may include malicious activity that is not in alignment with normal
behavior. It is critical to maintaining the security of
the network infrastructure and reduces the likelihood
of network intrusions.
Supervised methods are used to detect anomaly
trafﬁc [1–6]. For example, a machine learning classiﬁcation model, trained on appropriately labelled manual features, will declare anomaly trafﬁc when the
data does not follow the normal distribution. However, the main drawbacks of supervised anomaly detection are [7–10]:
(1) Collecting anomaly trafﬁc
would be a time-consuming and labor-intensive task
due to the nature of the anomaly trafﬁc; (2) It can
be challenging to obtain accurate and representative
introduce “noise”
normal
pseudo anomalies
(a) images
Can we get
pseudo anomalies?
introduce “noise”
normal
(b) packets
Figure 1: (a) Anomalies in images comprise of both colour
and shape. Based on prior knowledge of anomaly patterns,
images can simulate anomalies by introducing ”noise” [11,
12]. (b) Network trafﬁc anomaly patterns are difﬁcult to
generalise. Simulating abnormal network trafﬁc packets by
directly introducing ”noise” may destroy the semantic information of the data packets and produce meaningless pseudo
anomalies, as shown in Section 4.5. Our framework is able
to simulate anomaly samples without prior knowledge of
anomaly patterns.
labels for normal and abnor
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
*Source: arxiv | Paper ID: 50f1c704*
