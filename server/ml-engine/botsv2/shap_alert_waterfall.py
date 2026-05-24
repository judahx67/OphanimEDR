"""Per-event SHAP waterfalls for the honest LightGBM model.

Picks the highest-scoring true positive in each attack scenario (s200/s300/s400)
plus the highest-scoring false positive, then renders a SHAP waterfall plot for
each. Output is a single self-contained HTML file you can open in a browser or
embed in a thesis slide.

Usage:
    python shap_alert_waterfall.py
    # → models/lgbm_xt_temporal_no_st/eval/shap_alert_examples.html

The honest model is used because it is the one that drives alerts in
ml-edge-scorer (main.py uses score >= threshold for `is_alert`).
"""
from __future__ import annotations

import base64
import io
from pathlib import Path

import lightgbm as lgb
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import polars as pl
import shap

import schema as S

MODEL_DIR = Path(__file__).parent / "models" / "lgbm_xt_temporal_no_st"
TEST_PARQUET = Path(__file__).parent / "data" / "temporal" / "test.parquet"
OUT_HTML = MODEL_DIR / "eval" / "shap_alert_examples.html"

# How many examples per scenario to render
TOP_K_PER_SCENARIO = 2


def load_model() -> tuple[lgb.Booster, list[str], list[str]]:
    booster = lgb.Booster(model_file=str(MODEL_DIR / "booster.txt"))
    feature_names = booster.feature_name()
    cat_cols = S.model_categorical_columns()
    cat_cols = [c for c in cat_cols if c in feature_names]
    return booster, feature_names, cat_cols


def load_test_frame(feature_names: list[str], cat_cols: list[str]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (X aligned to model, meta_df with scenario/label/host).

    Categoricals are aligned to the categories.json (training-time vocab),
    matching what the production scorer does.
    """
    import json

    with open(MODEL_DIR / "categories.json") as f:
        train_cats = json.load(f)

    df = pl.read_parquet(TEST_PARQUET).to_pandas()

    meta_cols = ["scenario", "label", "host", "sourcetype", "_time",
                 "subject_name", "object_name"]
    meta = df[[c for c in meta_cols if c in df.columns]].copy()

    X = df[feature_names].copy()
    for c in cat_cols:
        cats = train_cats.get(c, [])
        X[c] = pd.Categorical(X[c], categories=cats)
    numeric_cols = [c for c in feature_names if c not in cat_cols]
    for c in numeric_cols:
        X[c] = pd.to_numeric(X[c], errors="coerce").astype("float64")
    return X, meta


def pick_examples(scores: np.ndarray, meta: pd.DataFrame) -> list[tuple[str, int]]:
    """Return list of (label_for_plot, row_index).

    Per scenario: top-K highest-scoring true positives.
    Plus: top FP overall (label=0 but score highest).
    """
    picks: list[tuple[str, int]] = []
    df = meta.copy()
    df["_score"] = scores
    df["_idx"] = np.arange(len(df))

    for scenario in ["s200_webapp_attack", "s300_ransomware", "s400_taedonggang_apt"]:
        tp = df[(df["scenario"] == scenario) & (df["label"] == 1)].nlargest(
            TOP_K_PER_SCENARIO, "_score"
        )
        for _, r in tp.iterrows():
            picks.append((
                f"TP / {scenario} / score={r['_score']:.3f} / "
                f"st={r.get('sourcetype', '?')} / host={r.get('host', '?')}",
                int(r["_idx"]),
            ))

    fp = df[df["label"] == 0].nlargest(2, "_score")
    for _, r in fp.iterrows():
        picks.append((
            f"FP / score={r['_score']:.3f} / "
            f"st={r.get('sourcetype', '?')} / host={r.get('host', '?')}",
            int(r["_idx"]),
        ))
    return picks


def render_waterfall(
    explainer: shap.TreeExplainer,
    X: pd.DataFrame,
    row_idx: int,
    title: str,
) -> str:
    """Run TreeExplainer on one row, return inline-SVG <img> tag."""
    row = X.iloc[[row_idx]]
    sv = explainer(row)
    # Binary LightGBM: shap returns array of shape (1, n_features) or
    # (1, n_features, 2) depending on version. Force 1d via .values.
    values = sv.values[0]
    base = sv.base_values[0] if np.ndim(sv.base_values) > 0 else float(sv.base_values)
    if values.ndim == 2:  # multiclass-shape, take the positive-class column
        values = values[:, 1]
        base = base[1] if hasattr(base, "__len__") else base

    expl = shap.Explanation(
        values=values,
        base_values=base,
        data=row.iloc[0].values,
        feature_names=list(X.columns),
    )

    fig = plt.figure(figsize=(9, 6))
    shap.plots.waterfall(expl, max_display=12, show=False)
    plt.title(title, fontsize=9, loc="left", wrap=True)
    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight")
    plt.close(fig)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f'<img alt="{title}" src="data:image/png;base64,{b64}" />'


def render_meta_row(meta: pd.DataFrame, idx: int) -> str:
    r = meta.iloc[idx]
    items = [
        f"<b>sourcetype</b> {r.get('sourcetype', '?')}",
        f"<b>host</b> {r.get('host', '?')}",
        f"<b>label</b> {r.get('label', '?')}",
        f"<b>scenario</b> {r.get('scenario', '?')}",
        f"<b>subject</b> {str(r.get('subject_name', ''))[:80]}",
        f"<b>object</b> {str(r.get('object_name', ''))[:80]}",
    ]
    return "<div class='meta'>" + " · ".join(items) + "</div>"


def main() -> int:
    print(f"Loading model from {MODEL_DIR}")
    booster, feature_names, cat_cols = load_model()
    print(f"  features: {len(feature_names)}  categorical: {len(cat_cols)}")

    print(f"Loading test parquet {TEST_PARQUET}")
    X, meta = load_test_frame(feature_names, cat_cols)
    print(f"  rows: {len(X):,}  positive: {int((meta['label'] == 1).sum()):,}")

    print("Scoring full test split (needed to pick top-K examples)…")
    scores = booster.predict(X)

    picks = pick_examples(scores, meta)
    print(f"Selected {len(picks)} examples for waterfall rendering")

    print("Building TreeExplainer (this allocates leaf SHAP values once)…")
    explainer = shap.TreeExplainer(booster)

    sections = []
    for title, idx in picks:
        print(f"  waterfall: {title}")
        img_tag = render_waterfall(explainer, X, idx, title)
        sections.append(
            f"<section><h2>{title}</h2>{render_meta_row(meta, idx)}{img_tag}</section>"
        )

    html = """<!doctype html>
<html><head><meta charset="utf-8">
<title>SHAP waterfalls — honest LightGBM (lgbm_xt_temporal_no_st)</title>
<style>
  body  {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           max-width: 1100px; margin: 2em auto; padding: 0 1em; color: #222; }}
  h1    {{ border-bottom: 2px solid #444; padding-bottom: .3em; }}
  h2    {{ font-size: 1.05em; margin-top: 2em; color: #333; }}
  .meta {{ font-size: 0.85em; color: #555; background: #f4f4f4;
           padding: .5em .8em; border-left: 3px solid #888; margin: .4em 0 .8em; }}
  img   {{ max-width: 100%; height: auto; border: 1px solid #ddd; }}
  .note {{ font-size: 0.85em; color: #444; background: #fffae6;
           border-left: 3px solid #d4a017; padding: .8em 1em; margin: 1em 0; }}
</style></head><body>
<h1>SHAP waterfalls — honest LightGBM (lgbm_xt_temporal_no_st)</h1>
<p class="note">
  Each plot shows how individual feature values push the log-odds away from
  the model's baseline (E[f(x)]) toward the final prediction f(x). Red bars
  push toward "malicious"; blue bars push toward "benign". The honest model
  does <i>not</i> see <code>sourcetype</code> — alert decisions are based on
  content features only.
</p>
{sections}
</body></html>
""".format(sections="\n".join(sections))

    OUT_HTML.parent.mkdir(parents=True, exist_ok=True)
    OUT_HTML.write_text(html, encoding="utf-8")
    print(f"\nWrote {OUT_HTML}  ({OUT_HTML.stat().st_size/1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
