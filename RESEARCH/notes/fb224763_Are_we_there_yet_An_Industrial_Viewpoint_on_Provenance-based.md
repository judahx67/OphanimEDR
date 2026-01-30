# Are we there yet? An Industrial Viewpoint on Provenance-based Endpoint Detection and Response Tools

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Feng Dong, Shaofei Li, Peng Jiang, Ding Li, Haoyu Wang |
| **Year** | 2023 |
| **Published** | 2023-07-17 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2307.08349v1 |
| **Paper URL** | http://arxiv.org/abs/2307.08349v1 |

---

## Citation

```
Feng Dong, Shaofei Li, Peng Jiang et al. (2023). "Are we there yet? An Industrial Viewpoint on Provenance-based Endpoint Detection and Response Tools". URL: http://arxiv.org/abs/2307.08349v1
```

---

## Abstract

Provenance-Based Endpoint Detection and Response (P-EDR) systems are deemed crucial for future APT defenses. Despite the fact that numerous new techniques to improve P-EDR systems have been proposed in academia, it is still unclear whether the industry will adopt P-EDR systems and what improvements the industry desires for P-EDR systems. To this end, we conduct the first set of systematic studies on the effectiveness and the limitations of P-EDR systems. Our study consists of four components: a one-to-one interview, an online questionnaire study, a survey of the relevant literature, and a systematic measurement study. Our research indicates that all industry experts consider P-EDR systems to be more effective than conventional Endpoint Detection and Response (EDR) systems. However, industry experts are concerned about the operating cost of P-EDR systems. In addition, our research reveals three significant gaps between academia and industry: (1) overlooking client-side overhead; (2) imbalanced alarm triage cost and interpretation cost; and (3) excessive server-side memory consumption. This paper’s findings provide objective data on the effectiveness of P-EDR systems and how much improvements are needed to adopt P-EDR systems in industry. 1

---

## Keywords/Categories

cs.CR

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
Xiao
Arizona State University
Xusheng.xiao@asu.edu
Jiedong Chen
Sangfor Technologies Inc.
chenjiedong1027@gmail.com
Xiapu Luo
The Hong Kong Polytechnic
University
csxluo@comp.polyu.edu.hk
Yao Guo†
Peking University
yaoguo@pku.edu.cn
Xiangqun Chen†
Peking University
cherry@sei.pku.edu.cn
ABSTRACT
Provenance-Based Endpoint Detection and Response (P-EDR) systems are deemed crucial for future APT defenses. Despite the fact
that numerous new techniques to improve P-EDR systems have
been proposed in academia, it is still unclear whether the industry
will adopt P-EDR systems and what improvements the industry
desires for P-EDR systems. To this end, we conduct the first set of
systematic studies on the effectiveness and the limitations of P-EDR
systems. Our study consists of four components: a one-to-one interview, an online questionnaire study, a survey of the relevant
literature, and a systematic measurement study. Our research indicates that all industry experts consider P-EDR systems to be more
effective than conventional Endpoint Detection and Response (EDR)
systems. However, industry experts are concerned about the operating cost of P-EDR systems. In addition, our research reveals three
significant gaps between academia and industry: (1) overlooking
client-side overhead; (2) imbalanced alarm triage cost and interpretation cost; and (3) excessive server-side memory consumption.
This paper’s findings provide objective data on the effectiveness of
P-EDR systems and how much improvements are needed to adopt
P-EDR systems in industry.
1
INTRODUCTION
P-EDR is a rising next-generation system for APT attack defending [21, 29, 35, 37, 56, 60, 81]. Compared with conventional EDR
∗Hubei Key Laboratory of Distributed System Security, Hubei Engineering Research
Center on Big Data Security, School of Cyber Science and Engineering, Huazhong
University of Science and Technology.
†Key Laboratory of High-Confidence Software Technologies (MOE), School of Computer Science, Peking University.
‡Co-corresponding authors.
systems, P-EDR systems introduce provenance graph, a data structure that models dependencies between system activities, so that
they can correlate multiple alarms, leading to higher detection accuracy and better interpretability [33]. As such, we have witnessed
a rapid growth of P-EDR research in the recent five years from
security/system top conferences and industry adoption of P-EDR
in commercial products. According to a recent study [40], there
are over 50 P-EDR related papers published in the most prestigious security (IEEE S&P, CCS, Usenix Security, NDSS) and systems (OSDI, SOSP, ATC) conferences in recent five years. Substantial research efforts have been put forth to improve P-EDR
systems in terms of system optimizations [35, 64, 76, 87], detection
algorithms [29, 33, 58, 61, 81, 89], and broader security applications [67, 79].
While these works have shown promising early results based
on evaluations in the academic setting, it is however still un
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
*Source: arxiv | Paper ID: fb224763*
