"""
AutoGluon multi-label trainer for per-Process MITRE-tactic classification.

Route 1 of the proposed pipeline: hand-crafted features → AutoGluon.
No rank-Gauss normalization, no denoising autoencoder.

Reverse-engineering mode (default ON):
    `fit_weighted_ensemble=False` + `num_bag_folds=0` + `num_stack_levels=0`
    so that `model_best` is a single base learner (LightGBM/XGBoost/CatBoost
    /RandomForest/...). This is essential because the thesis goal is to
    identify the *winning algorithm* and port it to PyTorch — a
    WeightedEnsemble_L2 stacker over 8 bagged models is unportable.

POC concessions:
    - 60s training time budget per tactic
    - `presets="medium_quality"`
    - tactics with <2 positives or all-positive get uniform 0.0 score
"""

import json
import logging
import os
import shutil
import tempfile
from collections import Counter

import pandas as pd

from feature_extractor import FEATURE_NAMES, TACTICS

log = logging.getLogger("ml-engine.trainer")

# Where to dump the per-tactic leaderboards + chosen-model artifacts.
# Volume-mounted in docker-compose so they survive container exit.
ARTIFACTS_DIR = os.environ.get("ML_ARTIFACTS_DIR", "/app/artifacts")


def _build_dataframe(rows: list[dict]) -> pd.DataFrame:
    records = []
    for r in rows:
        rec = {"uuid": r["uuid"]}
        rec.update({k: float(r["features"].get(k, 0.0)) for k in FEATURE_NAMES})
        rec.update({f"label__{t}": int(r["labels"].get(t, 0)) for t in TACTICS})
        records.append(rec)
    return pd.DataFrame.from_records(records)


def train_and_score(rows: list[dict]) -> list[dict]:
    """
    Train one binary AutoGluon predictor per MITRE tactic.

    Returns:
        list[{uuid, scores: {tactic: prob, ...}}]
    """
    if not rows:
        log.warning("No rows to train on")
        return []

    # Import here so the rest of the module can be loaded for tests
    # without paying the autogluon import cost up front.
    from autogluon.tabular import TabularPredictor

    df = _build_dataframe(rows)
    feature_cols = list(FEATURE_NAMES)
    uuids = df["uuid"].tolist()

    # Per-tactic probability matrix initialized to 0
    scores: dict[str, dict[str, float]] = {u: {t: 0.0 for t in TACTICS} for u in uuids}

    # Bookkeeping for the thesis report
    chosen_models: dict[str, str] = {}    # tactic -> winning algorithm
    leaderboards: dict[str, list[dict]] = {}
    val_scores: dict[str, float] = {}

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    train_root = tempfile.mkdtemp(prefix="autogluon_")
    try:
        for tactic in TACTICS:
            label_col = f"label__{tactic}"
            y = df[label_col]
            n_pos = int(y.sum())
            n_total = len(y)

            if n_pos < 2 or n_pos == n_total:
                log.info(
                    "Skip tactic '%s': %d / %d positives (insufficient)",
                    tactic, n_pos, n_total,
                )
                continue

            log.info(
                "Training tactic '%s': %d / %d positives",
                tactic, n_pos, n_total,
            )

            train_df = df[feature_cols + [label_col]].rename(
                columns={label_col: "label"}
            )
            tactic_path = os.path.join(train_root, tactic)

            # NOTE: configured for reverse-engineering. WeightedEnsemble +
            # bagging + stacking are all OFF so model_best is a single
            # base learner we can port to PyTorch.
            # POC dataset is tiny (~50 processes, single-digit positives
            # per tactic). roc_auc breaks when the validation fold has
            # only one class. f1 is robust to that and still
            # imbalance-aware. We use a tree-model zoo so the result
            # is portable to PyTorch (LightGBM / XGBoost / CatBoost /
            # RandomForest / ExtraTrees — all decision-tree based).
            predictor = TabularPredictor(
                label="label",
                problem_type="binary",
                eval_metric="f1",
                path=tactic_path,
                verbosity=1,
            ).fit(
                train_df,
                time_limit=60,
                presets="medium_quality",
                num_bag_folds=0,
                num_stack_levels=0,
                fit_weighted_ensemble=False,
                holdout_frac=0.2,
                hyperparameters={
                    "GBM": {},
                    "XGB": {},
                    "CAT": {},
                    "RF": {},
                    "XT": {},
                },
                raise_on_no_models_fitted=False,
            )

            # If literally nothing was trained (extreme imbalance),
            # skip this tactic.
            if not predictor.model_names():
                log.warning("No models fit for tactic '%s' — skipping",
                            tactic)
                continue

            # ── Inspect what AutoGluon actually picked ─────────────────
            try:
                lb = predictor.leaderboard(silent=True)
                lb_records = lb.to_dict(orient="records")
                leaderboards[tactic] = lb_records
                best_name = predictor.model_best
                chosen_models[tactic] = best_name
                # Validation score of the winning model
                try:
                    val_scores[tactic] = float(
                        lb[lb["model"] == best_name]["score_val"].iloc[0]
                    )
                except Exception:
                    val_scores[tactic] = float("nan")
                log.info(
                    "Tactic '%s' WINNER: %s  (val_score=%.4f)",
                    tactic, best_name, val_scores[tactic],
                )
            except Exception as exc:
                log.warning("leaderboard inspection failed for %s: %s", tactic, exc)

            # predict_proba returns prob-of-1 column when binary
            try:
                proba = predictor.predict_proba(df[feature_cols])
                if isinstance(proba, pd.DataFrame) and 1 in proba.columns:
                    p1 = proba[1]
                elif isinstance(proba, pd.DataFrame):
                    p1 = proba.iloc[:, -1]
                else:
                    p1 = pd.Series(proba)
            except Exception as exc:
                log.warning("predict_proba failed for tactic %s: %s", tactic, exc)
                continue

            for u, p in zip(uuids, p1.tolist()):
                scores[u][tactic] = float(p)
    finally:
        shutil.rmtree(train_root, ignore_errors=True)

    # ── Persist the experiment report ──────────────────────────────────
    report = {
        "tactics_trained": list(chosen_models.keys()),
        "tactics_skipped": [t for t in TACTICS if t not in chosen_models],
        "winning_models_per_tactic": chosen_models,
        "winning_model_distribution": dict(Counter(chosen_models.values())),
        "val_scores_per_tactic": val_scores,
        "leaderboards": leaderboards,
        "config": {
            "preset": "medium_quality",
            "time_limit_per_tactic_sec": 60,
            "num_bag_folds": 0,
            "num_stack_levels": 0,
            "fit_weighted_ensemble": False,
        },
    }
    report_path = os.path.join(ARTIFACTS_DIR, "experiment_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info("Experiment report written to %s", report_path)

    # Console summary — this is what the user actually wants to see
    log.info("=" * 60)
    log.info("EXPERIMENT SUMMARY — winning AutoGluon model per tactic")
    log.info("=" * 60)
    for t, m in chosen_models.items():
        log.info("  %-22s -> %-30s  (val=%.4f)",
                 t, m, val_scores.get(t, float("nan")))
    log.info("Algorithm distribution: %s",
             dict(Counter(chosen_models.values())))
    log.info("=" * 60)

    out = [{"uuid": u, "scores": scores[u]} for u in uuids]
    return out


# ── Score writeback ─────────────────────────────────────────────────────

def writeback(driver, scored: list[dict]) -> int:
    """
    Write per-tactic probabilities back onto Process nodes.

    Each Process gets:
        - ml_tactic_scores: map<string, float>   (full 11-tactic vector)
        - ml_top_tactic:    string               (argmax)
        - ml_max_score:     float                (max of the 11)
        - ml_score:         float                (alias of max — keeps the
                                                  old single-score API+UI working)
    """
    if not scored:
        return 0

    rows = []
    for s in scored:
        scores = s["scores"]
        top_tactic, max_score = max(scores.items(), key=lambda kv: kv[1])
        # Neo4j doesn't support map properties — serialize the per-tactic
        # vector as a JSON string. The API layer parses it back.
        rows.append({
            "uuid": s["uuid"],
            "scores_json": json.dumps(scores),
            "top": top_tactic,
            "max": float(max_score),
        })

    query = """
    UNWIND $rows AS row
    MATCH (p:Process {uuid: row.uuid})
    SET p.ml_tactic_scores = row.scores_json,
        p.ml_top_tactic    = row.top,
        p.ml_max_score     = row.max,
        p.ml_score         = row.max
    """
    with driver.session() as sess:
        sess.run(query, rows=rows)
    log.info("Wrote ml_tactic_scores to %d processes", len(rows))
    return len(rows)
