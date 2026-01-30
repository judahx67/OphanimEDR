# Preserving Privacy in Large Language Models: A Survey on Current Threats and Solutions

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Michele Miranda, Elena Sofia Ruzzetti, Andrea Santilli, Fabio Massimo Zanzotto, Sébastien Bratières |
| **Year** | 2024 |
| **Published** | 2024-08-10 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2408.05212v2 |
| **Paper URL** | http://arxiv.org/abs/2408.05212v2 |

---

## Citation

```
Michele Miranda, Elena Sofia Ruzzetti, Andrea Santilli et al. (2024). "Preserving Privacy in Large Language Models: A Survey on Current Threats and Solutions". URL: http://arxiv.org/abs/2408.05212v2
```

---

## Abstract

Large Language Models (LLMs) represent a significant advancement in artificial intelligence, finding applications across various domains. However, their reliance on massive internetsourced datasets for training brings notable privacy issues exacerbated in critical domains (e.g., healthcare). Moreover, certain application-specific scenarios may require fine-tuning these models on private data. This survey critically examines the privacy threats associated with LLMs, emphasizing the potential for these models to memorize and inadvertently reveal sensitive information. We explore current threats by reviewing privacy attacks on LLMs and propose comprehensive solutions for integrating privacy mechanisms throughout the entire learning pipeline. These solutions range from anonymizing training datasets to implementing differential privacy during training or inference and machine unlearning after training. Our comprehensive review of existing literature highlights ongoing challenges, available tools, and future directions for preserving privacy in LLMs. This work aims to guide the development of more secure and trustworthy AI systems by providing a thorough understanding of privacy preservation methods and their effectiveness in mitigating risks. 1 arXiv:2408.05212v2 [cs.CR] 10 Feb 2025 --- Page 2 --- Published in Transactions on Machine Learning Research (01/2025) Contents 1

---

## Keywords/Categories

cs.CR, cs.AI, cs.CL, cs.LG

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
atières
sebastien@translated.com
Translated
Emanuele Rodolà
rodola@di.uniroma1.it
Sapienza University of Rome
Reviewed on OpenReview: https://openreview.net/forum?id=Ss9MTTN7OL
Abstract
Large Language Models (LLMs) represent a significant advancement in artificial intelligence,
finding applications across various domains. However, their reliance on massive internetsourced datasets for training brings notable privacy issues exacerbated in critical domains
(e.g., healthcare). Moreover, certain application-specific scenarios may require fine-tuning
these models on private data. This survey critically examines the privacy threats associated
with LLMs, emphasizing the potential for these models to memorize and inadvertently
reveal sensitive information. We explore current threats by reviewing privacy attacks on
LLMs and propose comprehensive solutions for integrating privacy mechanisms throughout
the entire learning pipeline. These solutions range from anonymizing training datasets to
implementing differential privacy during training or inference and machine unlearning after
training.
Our comprehensive review of existing literature highlights ongoing challenges,
available tools, and future directions for preserving privacy in LLMs. This work aims to
guide the development of more secure and trustworthy AI systems by providing a thorough
understanding of privacy preservation methods and their effectiveness in mitigating risks.
1
arXiv:2408.05212v2 [cs.CR] 10 Feb 2025

--- Page 2 ---

Published in Transactions on Machine Learning Research (01/2025)
Contents
1
Introduction
4
2
Preliminaries
7
2.1
Large Language Models
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
7
2.2
Differential Privacy . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
9
2.3
Deep Learning with Differential Privacy . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
12
3
Privacy Attacks
14
3.1
Training Data Extraction
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
15
3.1.1
Non-adversarial extraction . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
16
3.1.2
Adversarial prompting . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
17
3.2
Membership Inference Attacks (MIA)
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
18
3.2.1
MIA with Thresholds
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
18
3.3
Model Inversion and Stealing . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
19
3.3.1
Model Output Inversion and Model Stealing . . . . . . . . . . . . . . . . . . . . . . . .
20
3.3.2
Gradient Inversion . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
21
3.3.3
Model Stealing . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
21
3.4
Privacy Threats at Inference Time. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
22
4
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
*Source: arxiv | Paper ID: 4b9afa41*
