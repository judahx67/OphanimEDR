# LeakGuard: Detecting Memory Leaks Accurately and Scalably

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Hongliang Liang, Luming Yin, Guohao Wu, Yuxiang Li, Qiuping Yi |
| **Year** | 2025 |
| **Published** | 2025-04-06 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2504.04422v1 |
| **Paper URL** | http://arxiv.org/abs/2504.04422v1 |

---

## Citation

```
Hongliang Liang, Luming Yin, Guohao Wu et al. (2025). "LeakGuard: Detecting Memory Leaks Accurately and Scalably". URL: http://arxiv.org/abs/2504.04422v1
```

---

## Abstract

Memory leaks are prevalent in various real-world software projects, thereby leading to serious attacks like denial-of-service. Though prior methods for detecting memory leaks made significant advance, they often suffer from low accuracy and weak scalability for testing large and complex programs. In this paper we present LeakGuard, a memory leak detection tool which provides satisfactory balance of accuracy and scalability. For accuracy, LeakGuard analyzes the behaviors of library and developer-defined memory allocation and deallocation functions in a path-sensitive manner and generates function summaries for them in a bottom-up approach. Additionally, we develop a pointer escape analysis technique to model the transfer of pointer ownership. For scalability, LeakGuard examines each function of interest independently by using its function summary and under-constrained symbolic execution technique, which effectively mitigates path explosion problem. Our extensive evaluation on 18 real-world software projects and standard benchmark datasets demonstrates that LeakGuard achieves significant advancements in multiple aspects: it exhibits superior MAD function identification capability compared to Goshawk, outperforms five state-of-the-art methods in defect detection accuracy, and successfully identifies 129 previously undetected memory leak bugs, all of which have been independently verified and confirmed by the respective development teams. Keywords Memory Leaks, Under-Constrained Symbolic Execution, Pointer Escape Analysis Hongliang Liang (Corresponding author) TSIS Lab., Beijing University of Posts and Telecommunications E-mail: hliang@bupt.edu.cn Luming Yin TSIS Lab., Beijing University of Posts and Telecommunications E-mail: lumingying@bupt.edu.cn Guohao Wu TSIS Lab., Beijing University of Posts and Telecommunications E-mail: guohaowu@bupt.edu.cn Yuxiang Li TSIS Lab., Beijing University of Posts and Telecommunications E-mail: liyuxiang@bupt.edu.cn Qiuping Yi TSIS Lab., Beijing University of Posts and Telecommunications E-mail: yiqiuping@bupt.edu.cn Lei Wang TSIS Lab., Beijing University of Posts and Telecommunications E-mail: wangcppclei@gmail.com arXiv:2504.04422v1 [cs.CR] 6 Apr 2025

---

## Keywords/Categories

cs.CR, cs.SE

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
accuracy and weak scalability for testing large and complex programs. In this paper we present LeakGuard, a memory leak detection tool which provides
satisfactory balance of accuracy and scalability. For accuracy, LeakGuard analyzes the behaviors
of library and developer-defined memory allocation and deallocation functions in a path-sensitive
manner and generates function summaries for them in a bottom-up approach. Additionally, we
develop a pointer escape analysis technique to model the transfer of pointer ownership. For scalability, LeakGuard examines each function of interest independently by using its function summary
and under-constrained symbolic execution technique, which effectively mitigates path explosion
problem. Our extensive evaluation on 18 real-world software projects and standard benchmark
datasets demonstrates that LeakGuard achieves significant advancements in multiple aspects: it
exhibits superior MAD function identification capability compared to Goshawk, outperforms five
state-of-the-art methods in defect detection accuracy, and successfully identifies 129 previously
undetected memory leak bugs, all of which have been independently verified and confirmed by the
respective development teams.
Keywords Memory Leaks, Under-Constrained Symbolic Execution, Pointer Escape Analysis
Hongliang Liang (Corresponding author)
TSIS Lab., Beijing University of Posts and Telecommunications
E-mail: hliang@bupt.edu.cn
Luming Yin
TSIS Lab., Beijing University of Posts and Telecommunications
E-mail: lumingying@bupt.edu.cn
Guohao Wu
TSIS Lab., Beijing University of Posts and Telecommunications
E-mail: guohaowu@bupt.edu.cn
Yuxiang Li
TSIS Lab., Beijing University of Posts and Telecommunications
E-mail: liyuxiang@bupt.edu.cn
Qiuping Yi
TSIS Lab., Beijing University of Posts and Telecommunications
E-mail: yiqiuping@bupt.edu.cn
Lei Wang
TSIS Lab., Beijing University of Posts and Telecommunications
E-mail: wangcppclei@gmail.com
arXiv:2504.04422v1 [cs.CR] 6 Apr 2025

--- Page 2 ---

2
Hongliang Liang et al.
1 Introduction
Memory leaks refer to situations where a memory regions dynamically allocated by functions such as
malloc, calloc, or the new operator, is not properly released after their use. These unused memory
regions cannot be reclaimed by the operating system, leading to depletion of system resources.
Memory leak bugs in programs can be maliciously exploited by attackers, potentially resulting
in denial-of-service attacks. Research shows that many small or uncommon memory leak defects
can also lead to similar consequences (Cantrill, 2003). As of July 2024, there are over 1,700 CVEs
(Common Vulnerabilities and Exposures) related to memory leaks. Memory leaks have become a
significant factor compromising the security of computer systems.
Except for the standard functions like malloc or free, in real-world programs, developers
often write their own MAD functions that manage multiple memory objects by invoking standard
functions directly or indirect
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
*Source: arxiv | Paper ID: 81fbeb3c*
