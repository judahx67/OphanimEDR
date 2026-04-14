"""
XGBoost trainer + score writeback.

- Trains a binary classifier on per-process graph features.
- Writes ml_score (0-1 probability) back onto each Process node in Neo4j.

POC crude: no CV, no hyperparam search. If too few positives, falls back
to a heuristic score (normalized out-degree) so the dashboard still shows
something.
"""

import logging

import numpy as np
import xgboost as xgb

from feature_extractor import FEATURE_NAMES

log = logging.getLogger("ml-engine.trainer")


def _build_matrix(rows: list[dict]) -> tuple[np.ndarray, np.ndarray, list[str]]:
    X = np.array(
        [[r["features"][k] for k in FEATURE_NAMES] for r in rows],
        dtype=np.float32,
    )
    y = np.array([r["label"] for r in rows], dtype=np.int32)
    uuids = [r["uuid"] for r in rows]
    return X, y, uuids


def _heuristic_score(X: np.ndarray) -> np.ndarray:
    """Fallback when we can't train (no positives): normalize out-degree."""
    out_degree = X[:, FEATURE_NAMES.index("out_degree")]
    if out_degree.max() == 0:
        return np.zeros_like(out_degree)
    return out_degree / out_degree.max()


def train_and_score(rows: list[dict]) -> list[tuple[str, float]]:
    if not rows:
        log.warning("No processes to score")
        return []

    X, y, uuids = _build_matrix(rows)
    n_pos = int(y.sum())
    n_total = len(y)

    if n_pos < 2 or n_pos == n_total:
        log.warning(
            "Insufficient labels for training (%d pos / %d total); "
            "using heuristic score",
            n_pos,
            n_total,
        )
        scores = _heuristic_score(X)
    else:
        scale_pos_weight = (n_total - n_pos) / max(n_pos, 1)
        log.info(
            "Training XGBoost: %d samples, %d positives, scale_pos_weight=%.2f",
            n_total,
            n_pos,
            scale_pos_weight,
        )
        model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            tree_method="hist",
        )
        model.fit(X, y)
        scores = model.predict_proba(X)[:, 1]

        importances = dict(zip(FEATURE_NAMES, model.feature_importances_))
        top = sorted(importances.items(), key=lambda x: -x[1])[:5]
        log.info("Top features: %s", top)

    return list(zip(uuids, scores.tolist()))


def writeback(driver, scored: list[tuple[str, float]]) -> int:
    if not scored:
        return 0

    query = """
    UNWIND $rows AS row
    MATCH (p:Process {uuid: row.uuid})
    SET p.ml_score = row.score
    """
    rows = [{"uuid": u, "score": float(s)} for u, s in scored]
    with driver.session() as sess:
        sess.run(query, rows=rows)
    log.info("Wrote ml_score to %d processes", len(rows))
    return len(rows)
