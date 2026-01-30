# Improving Network Threat Detection by Knowledge Graph, Large Language Model, and Imbalanced Learning

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Lili Zhang, Quanyan Zhu, Herman Ray, Ying Xie |
| **Year** | 2025 |
| **Published** | 2025-01-26 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2501.16393v2 |
| **Paper URL** | http://arxiv.org/abs/2501.16393v2 |

---

## Citation

```
Lili Zhang, Quanyan Zhu, Herman Ray et al. (2025). "Improving Network Threat Detection by Knowledge Graph, Large Language Model, and Imbalanced Learning". URL: http://arxiv.org/abs/2501.16393v2
```

---

## Abstract

Network threat detection is challenging due to the complex nature of attack activities and the limited availability of historical threat data to learn from. To help enhance the existing methods (e.g., analytics, machine learning, and artificial intelligence) to detect the network threats, we propose a multi-agent AI solution for agile threat detection. In this solution, a Knowledge Graph is used to analyze changes in user activity patterns and calculate the risk of unknown threats. Then, an Imbalanced Learning Model is used to prune and weigh the Knowledge Graph, and also calculate the risk of known threats. Finally, a Large Language Model (LLM) is used to retrieve and interpret the risk of user activities from the Knowledge Graph and the Imbalanced Learning Model. The preliminary results show that the solution improves the threat capture rate by 3%-4% and adds natural language interpretations of the risk predictions based on user activities. Furthermore, a demo application has been built to show how the proposed solution framework can be deployed and used.

---

## Keywords/Categories

cs.LG, cs.CR, stat.ML

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
on for agile threat detection. In this solution, a Knowledge Graph
is used to analyze changes in user activity patterns and calculate the risk of unknown threats.
Then, an Imbalanced Learning Model is used to prune and weigh the Knowledge Graph, and
also calculate the risk of known threats. Finally, a Large Language Model (LLM) is used to
retrieve and interpret the risk of user activities from the Knowledge Graph and the Imbalanced
Learning Model. The preliminary results show that the solution improves the threat capture
rate by 3%-4% and adds natural language interpretations of the risk predictions based on user
activities. Furthermore, a demo application has been built to show how the proposed solution
framework can be deployed and used.
Keywords: network threat detection, knowledge graph, large language model, imbalanced
learning, multi-agent AI
1
Introduction
Network threats have brought significant financial losses and public safety issues in recent years.
The total reported loss from cybercrimes is more than $12. 5 billion in the US in 2023 according
to the FBI’s Internet Crime Complaint Center (IC3) report [FBI, 2024]. Moreover, public safety
systems face increasing disruption in emergency communication systems and operations due to
malicious attacks [CISA, 2023]. These are caused by more complicated and new network attack
activities that are not detected in time [Zhu et al., 2012]. This presents a significant need for
Agile Threat Detection, which aims to identify and respond to evolving threats rapidly and
proactively [Zhu, 2024].
The analytics, machine learning (ML) and artificial intelligence (AI) methods have been
widely used by researchers and practitioners to discover the patterns of known threats and
detect unusual signals of unknown threats from the activities of users.
Traditional ML/AI
models typically need a lot of historical data to learn from to guarantee good model performance.
However, there are very limited historical data on known threats that have been observed but are
not detected every time they occur. And there is no data on unknown threats that have never
been observed before. These challenge traditional ML/AI models to predict network threats
accurately.
∗Hewlett Packard Enterprise
†New York University
‡Kennesaw State University
§Kennesaw State University
1
arXiv:2501.16393v2 [cs.LG] 14 May 2025

--- Page 2 ---

Compared to other ML / AI models only, Knowledge Graph shows a higher efficiency in
analyzing user activities and their relationships to discover abnormalities. However, it has three
challenges. The first is to prune and weigh the information properly in the graph to filter out
weak or redundant information for network threats. The second is to include large texts as a
part of graphs and graph analysis. The third is to unravel, diagnose, and interpret the complex
activities and relationships of users in the graph.
To overcome the challenges above, we propose to better detect the network threats by the
combin
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
*Source: arxiv | Paper ID: ca3934bf*
