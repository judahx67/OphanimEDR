# Meta-UAD: A Meta-Learning Scheme for User-level Network Traffic Anomaly Detection

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Tongtong Feng, Qi Qi, Lingqi Guo, Jingyu Wang |
| **Year** | 2024 |
| **Published** | 2024-08-30 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2408.17031v2 |
| **Paper URL** | http://arxiv.org/abs/2408.17031v2 |

---

## Citation

```
Tongtong Feng, Qi Qi, Lingqi Guo et al. (2024). "Meta-UAD: A Meta-Learning Scheme for User-level Network Traffic Anomaly Detection". URL: http://arxiv.org/abs/2408.17031v2
```

---

## Abstract

Accuracy anomaly detection in user-level network traffic is crucial for network security. Compared with existing models that passively detect specific anomaly classes with large labeled training samples, user-level network traffic contains sizeable new anomaly classes with few labeled samples and has an imbalance, self-similar, and data-hungry nature. Motivation on those limitations, in this paper, we propose \textit{Meta-UAD}, a Meta-learning scheme for User-level network traffic Anomaly Detection. Meta-UAD uses the CICFlowMeter to extract 81 flow-level statistical features and remove some invalid ones using cumulative importance ranking. Meta-UAD adopts a meta-learning training structure and learns from the collection of K-way-M-shot classification tasks, which can use a pre-trained model to adapt any new class with few samples by few iteration steps. We evaluate our scheme on two public datasets. Compared with existing models, the results further demonstrate the superiority of Meta-UAD with 15{\%} - 43{\%} gains in F1-score.

---

## Keywords/Categories

cs.CR

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
 anomaly classes with large
labeled training samples, user-level network traffic contains
sizeable new anomaly classes with few labeled samples and has
an imbalance, self-similar, and data-hungry nature. Motivation
on those limitations, in this paper, we propose Meta-UAD, a
Meta-learning scheme for User-level network traffic Anomaly
Detection. Meta-UAD uses the CICFlowMeter to extract 81 flowlevel statistical features and remove some invalid ones using cumulative importance ranking. Meta-UAD adopts a meta-learning
training structure and learns from the collection of K-way-Mshot classification tasks, which can use a pre-trained model to
adapt any new class with few samples by few iteration steps.
We evaluate our scheme on two public datasets. Compared with
existing models, the results further demonstrate the superiority
of Meta-UAD with 15% - 43% gains in F1-score.
Index Terms—Anomaly Detection, Network Traffic, Few-Shot
Learning, Meta-Learning
I. INTRODUCTION
Accuracy anomaly detection in user-level traffic is crucial
for network security [1]. Attackers might exploit an application
containing a vulnerability, jeopardizing the confidentiality,
integrity, and availability of the user’s crucial information.
User-level network traffic contains sizeable new anomaly
classes with few labeled samples. Those new anomaly classes
possess three unique characteristics. Imbalanced [2], [3]:
compared to the existing anomaly classes, it is expensive
and arduous to collect a massive amount of data onto the
new anomaly class. Therefore, the sample sizes of different
anomaly classes in the sampled database are often highly
imbalanced. Self-similar [4], [5]: the new anomaly classes
evolve from the existing ones and have characteristics closer
to normal traffic. As our detection models adapt, so does
anomaly traffic. According to the McAfee labs threats reports1,
most new anomaly classes are branches of existing anomaly
families. Data-hungry [6], [7]: now more attackers are focusing on fewer but more precise targets instead of widespread
invasions, so each new anomaly class has small-scale samples.
According to the CrowdStrike report2, near 62% attackers will
remain silent until a precise target is discovered, and they use
⋆Corresponding author.
1https://media.mcafeeassets.com/content/dam/npcld/ecommerce/enus/docs/reports/rp-mobile-threat-report-feb-2023.pdf.
2https://www.crowdstrike.com/global-threat-report/.
User-level Network Traffic Anomaly Detection
Meta Model
Anomaly families:
Normal samples:
Anomaly samples:
Classification Model
(1)
(3)
Model Update
(2)
Model Update
Classification Model
Training Phase
Sample Generator
(1)
(2)
(1)
(2)
Testing Phase
Machine-learning based
Metric- or generative- based
Meta-learning based
Feature Matrix
Fig. 1. Network traffic anomaly detection schemes.
legitimate credentials and built-in tools to attack, which can
avoid detection by traditional detection models.
Existing anomaly detection models can be grouped into
three categori
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
*Source: arxiv | Paper ID: e70fe222*
