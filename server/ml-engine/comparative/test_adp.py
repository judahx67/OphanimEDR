"""Unit tests for adp.compute_adp / relative_adp_std.

Run: python -m pytest server/ml-engine/comparative/test_adp.py -q
(or:  python server/ml-engine/comparative/test_adp.py  for the no-pytest fallback)
"""
import math

import numpy as np
import pytest

from adp import BENIGN, compute_adp, relative_adp_std


def test_perfect_single_attack():
    # 1 attack, its node is the top score, no FP before it -> precision 1.0, full coverage.
    scores = np.array([0.9, 0.5, 0.4, 0.3])
    aids = np.array([0, BENIGN, BENIGN, BENIGN])
    assert compute_adp(scores, aids) == pytest.approx(1.0)


def test_perfect_multi_attack_orthrus():
    # 3 attacks, one node each, all are the top-3 scores with zero FP -> ADP == 1.0.
    scores = np.array([0.99, 0.98, 0.97, 0.5, 0.4, 0.3, 0.2])
    aids = np.array([0, 1, 2, BENIGN, BENIGN, BENIGN, BENIGN])
    assert compute_adp(scores, aids) == pytest.approx(1.0)


def test_kairos_like_buried_single_attack():
    # 1 malicious node buried under 100 higher-scored benign nodes.
    # Coverage only reaches 1.0 at precision 1/101 -> ADP ~= 1/101 ~ 0.0099 (paper: KAIROS 0.01).
    n_benign = 100
    scores = np.concatenate([np.linspace(1.0, 0.1, n_benign), [0.0]])
    aids = np.array([BENIGN] * n_benign + [0])
    assert compute_adp(scores, aids) == pytest.approx(1.0 / (n_benign + 1), abs=1e-9)


def test_two_attacks_one_clean_one_buried():
    # Attack 0 detected cleanly at precision 1.0 (top node); attack 1 buried.
    # At precision 1.0 we cover 1/2 attacks -> D(p)=0.5 for all p<=1.0 from the clean point;
    # the buried attack lifts D to 1.0 only at a tiny precision. ADP ~= 0.5 + small.
    scores = np.array([0.99, 0.8, 0.7, 0.6, 0.5, 0.05])
    aids = np.array([0, BENIGN, BENIGN, BENIGN, BENIGN, 1])
    adp = compute_adp(scores, aids)
    # clean attack -> D=0.5 over all p; buried attack coverable at precision 2/6=1/3
    # lifts D to 1.0 for p<=1/3, adding 0.5*(1/3). ADP = 0.5 + 0.5*(1/3) = 2/3.
    assert adp == pytest.approx(2.0 / 3.0, abs=1e-9)


def test_tie_safety_independent_of_order():
    # Tied scores across a benign and a malicious node: result must not depend on input order.
    a = np.array([0.5, 0.5, 0.1])
    ids1 = np.array([0, BENIGN, BENIGN])
    ids2 = np.array([BENIGN, 0, BENIGN])
    assert compute_adp(a, ids1) == compute_adp(a, ids2)
    # tie group {mal, benign} at top -> precision 0.5 at coverage 1.0 -> ADP == 0.5
    assert compute_adp(a, ids1) == pytest.approx(0.5)


def test_no_attacks_raises():
    with pytest.raises(ValueError):
        compute_adp(np.array([0.1, 0.2]), np.array([BENIGN, BENIGN]))


def test_shape_mismatch_raises():
    with pytest.raises(ValueError):
        compute_adp(np.array([0.1, 0.2, 0.3]), np.array([BENIGN, 0]))


def test_relative_adp_std_instability():
    # Orthrus-on-THEIA style swing 1.0 -> ~0.1 across seeds: high relative std.
    rel = relative_adp_std([1.0, 1.0, 0.1, 0.9, 0.2])
    assert rel > 0.3
    # stable run -> ~0
    assert relative_adp_std([1.0, 1.0, 1.0]) == pytest.approx(0.0)
    assert math.isnan(relative_adp_std([0.0, 0.0]))


if __name__ == "__main__":  # no-pytest fallback
    import adp as _adp

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
