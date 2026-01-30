# Multimedia Traffic Anomaly Detection

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Tongtong Feng, Qi Qi, Jingyu Wang |
| **Year** | 2024 |
| **Published** | 2024-08-27 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2408.14884v3 |
| **Paper URL** | http://arxiv.org/abs/2408.14884v3 |

---

## Citation

```
Tongtong Feng, Qi Qi, Jingyu Wang (2024). "Multimedia Traffic Anomaly Detection". URL: http://arxiv.org/abs/2408.14884v3
```

---

## Abstract

Accuracy anomaly detection in user-level social multimedia traffic is crucial for privacy security. Compared with existing models that passively detect specific anomaly classes with large labeled training samples, user-level social multimedia traffic contains sizeable new anomaly classes with few labeled samples and has an imbalance, self-similar, and data-hungry nature. Recent advances, such as Generative Adversarial Networks (GAN), solve it by learning a sample generator only from seen class samples to synthesize new samples. However, if we detect many new classes, the number of synthesizing samples would be unfeasibly estimated, and this operation will drastically increase computational complexity and energy consumption. Motivation on these limitations, in this paper, we propose \textit{Meta-UAD}, a Meta-learning scheme for User-level social multimedia traffic Anomaly Detection. This scheme relies on the episodic training paradigm and learns from the collection of K-way-M-shot classification tasks, which can use the pre-trained model to adapt any new class with few samples by going through few iteration steps. Since user-level social multimedia traffic emerges from a complex interaction process of users and social applications, we further develop a feature extractor to improve scheme performance. It extracts statistical features using cumulative importance ranking and time-series features using an LSTM-based AutoEncoder. We evaluate our scheme on two public datasets and th

---

## Keywords/Categories

cs.CR

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
affic
contains sizeable new anomaly classes with few labeled samples
and has an imbalance, self-similar, and data-hungry nature.
Recent advances, such as Generative Adversarial Networks
(GAN), solve it by learning a sample generator only from seen
class samples to synthesize new samples. However, if we detect
many new classes, the number of synthesizing samples would be
unfeasibly estimated, and this operation will drastically increase
computational complexity and energy consumption. Motivation
on these limitations, in this paper, we propose Meta-UAD, a Metalearning scheme for User-level social multimedia traffic Anomaly
Detection. This scheme relies on the episodic training paradigm
and learns from the collection of K-way-M-shot classification
tasks, which can use the pre-trained model to adapt any new
class with few samples by going through few iteration steps.
Since user-level social multimedia traffic emerges from a complex
interaction process of users and social applications, we further
develop a feature extractor to improve scheme performance. It
extracts statistical features using cumulative importance ranking
and time-series features using an LSTM-based AutoEncoder.
We evaluate our scheme on two public datasets and the results
further demonstrate the superiority of Meta-UAD.
Index Terms—Social Mutimedia Traffic, Anomaly Detection,
Few-Shot Learning, Meta-Learning
I. INTRODUCTION
S
OCIAL multimedia can keep in touch with friends and
family, fill spare time, see what’s being talked about,
find articles and videos, including famous Facebook, YouTube,
WhatsApp, WeChat platforms and having become inseparable
from people’s daily life. Analysis from Kepios1 shows that
there are 4.74 billion social multimedia users around the world
in October 2022, equating to 93.4% internet users or 75.4%
of the total global population aged 13 and above2. Data from
Cisco3 reveals that social multimedia traffic will account for
82% of all Internet traffic by 2022.
Accuracy anomaly detection in social multimedia traffic is
crucial for privacy security [1]–[5]. Conclusion from Report4
Tongtong Feng is with the department of computer science and technology, Tsinghua University, Beijing 100084, China (e-mail: fengtongtong@tsinghua.edu.cn). Qi Qi and Jingyu Wang are with the State Key
Laboratory of Networking and Switching Technology, Beijing University
of Posts and Telecommunications, Beijing 100876, China and also with
the EBUPT.COM, Beijing 100191, China (e-mail: qiqi8266@bupt.edu.cn;
wangjingyu@bupt.edu.cn).
1https://kepios.com/.
2https://datareportal.com/social-media-users/.
3https://www.cisco.com/c/en/us/solutions/collateral/service-provider/visualnetworking-index-vni/complete-white-paper-c11-481360.html.
4https://www.insiderintelligence.com/content/digital-trust-benchmarkreport-2021.
counts that 52% social multimedia users are strongly concerned about platforms’ protection of their privacy and data.
Attackers might exploit applications containing vulnerability,
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
*Source: arxiv | Paper ID: e984626d*
