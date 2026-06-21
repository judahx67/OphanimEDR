"""ADP — Area under the Detection-Precision curve (Bilot et al., USENIX Sec'25, SC2).

A threshold-independent, multi-attack detection metric. Unlike precision/recall it
does not depend on a chosen operating threshold, and unlike AUC-ROC / AP it rewards
detecting >=1 node *per distinct attack* rather than every malicious node.

Definition (paper):
  - k          = number of distinct attacks in the ground truth.
  - R(p)       = set of nodes flagged when operating at precision p.
  - D(p)       = (1/k) * #{ attacks i : A_i ∩ R(p) != ∅ }   -- fraction of attacks hit.
  - ADP        = ∫₀¹ D(p) dp.

We compute the interpolated detection-precision curve the same way Average Precision
interpolates precision: D(p) = max{ D_j : precision_j >= p }, integrated exactly over
p ∈ [0, 1]. Operating points are taken only at score-group boundaries so the result is
independent of how tied scores happen to be ordered.

Reported reference values (E3-CADETS, paper Fig.3): KAIROS 0.01, NODLINK 0.96, ORTHRUS 1.00.

The same `compute_adp` is meant to be applied to the per-node score vectors of *every*
scorer under comparison (Orthrus, FLASH, our GAT, the composition-floor control) so the
comparison is on one metric, one substrate.
"""
from __future__ import annotations

import numpy as np

BENIGN = -1  # sentinel attack id for benign nodes


def _operating_points(scores: np.ndarray, attack_ids: np.ndarray, n_attacks: int):
    """Yield (precision, detection_fraction) at each descending score-group boundary.

    A node is malicious iff attack_ids[i] != BENIGN. Precision and attack-coverage are
    evaluated on the prefix of all nodes with score >= the current group's score.
    """
    order = np.argsort(-scores, kind="stable")
    s = scores[order]
    a = attack_ids[order]

    seen = set()
    n_mal = 0
    pts = []
    i = 0
    n = len(s)
    while i < n:
        j = i
        # consume all nodes sharing this score (tie group)
        while j < n and s[j] == s[i]:
            if a[j] != BENIGN:
                n_mal += 1
                seen.add(int(a[j]))
            j += 1
        k = j  # prefix length = nodes with score >= s[i]
        precision = n_mal / k
        det_frac = len(seen) / n_attacks
        pts.append((precision, det_frac))
        i = j
    return pts


def compute_adp(scores, attack_ids) -> float:
    """ADP for one scorer's per-node scores.

    scores      : array-like, per-node anomaly score (higher = more anomalous).
    attack_ids  : array-like, same length; integer attack id for malicious nodes,
                  BENIGN (-1) for benign nodes.
    Returns ADP ∈ [0, 1]. Raises if there are no malicious nodes.
    """
    scores = np.asarray(scores, dtype=np.float64)
    attack_ids = np.asarray(attack_ids)
    if scores.shape != attack_ids.shape:
        raise ValueError("scores and attack_ids must have the same shape")

    attacks = {int(x) for x in attack_ids if int(x) != BENIGN}
    n_attacks = len(attacks)
    if n_attacks == 0:
        raise ValueError("no malicious nodes (no attack ids) -> ADP undefined")

    pts = _operating_points(scores, attack_ids, n_attacks)

    # Interpolated D(p) = max{ D_j : precision_j >= p }, integrated exactly over [0,1].
    pts.sort(key=lambda t: t[0])          # ascending precision
    prec = [p for p, _ in pts]
    dfrac = [d for _, d in pts]
    suffix_max = [0.0] * len(pts)
    run = 0.0
    for idx in range(len(pts) - 1, -1, -1):
        run = max(run, dfrac[idx])
        suffix_max[idx] = run

    adp = 0.0
    prev_p = 0.0
    for idx in range(len(pts)):
        width = prec[idx] - prev_p
        if width > 0:
            adp += width * suffix_max[idx]    # f(p) for p in (prev_p, prec[idx]]
        prev_p = prec[idx]
    # tail p ∈ (prev_p, 1] contributes 0 (no operating point reaches that precision)
    return float(adp)


def relative_adp_std(adp_values, ddof: int = 0) -> float:
    """Relative ADP std (σ̃_ADP, paper SC5) = std(ADP) / mean(ADP) over T seeds.

    Quantifies instability across identical re-runs with different seeds. The paper
    reports deviations approaching 100% for several systems (e.g. Orthrus on E3-THEIA
    swings 1.0 -> <0.1 across seeds). ddof=0 (population std) by default.
    """
    vals = np.asarray(adp_values, dtype=np.float64)
    mean = vals.mean()
    if mean == 0:
        return float("nan")
    return float(vals.std(ddof=ddof) / mean)


def _main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Compute ADP from an exported score file.")
    ap.add_argument("path", help=".npz with arrays 'scores' and 'attack_ids' (benign = -1)")
    args = ap.parse_args()
    d = np.load(args.path)
    print(f"ADP = {compute_adp(d['scores'], d['attack_ids']):.4f}")


if __name__ == "__main__":
    _main()
