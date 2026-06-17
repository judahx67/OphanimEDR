"""
Load frozen LightGBM boosters + their category dictionaries.

Each model directory contains:
  booster.txt        — LightGBM text-format model
  categories.json    — {column_name: [cat_value, ...]} for all categorical features
  feature_names.json — ordered list of feature columns
  threshold.json     — {"threshold": float, ...}
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import lightgbm as lgb


def _load_booster_safe(model_path: Path) -> lgb.Booster:
    """Load a LightGBM booster, normalising CRLF → LF first.

    Docker volume mounts on Windows pass CRLF files to Linux containers.
    LightGBM's C++ parser chokes on \\r at line ends — strip them via a
    temp file so the source file on disk is never modified.
    """
    raw = model_path.read_bytes()
    if b"\r\n" in raw:
        normalized = raw.replace(b"\r\n", b"\n")
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="wb") as tmp:
            tmp.write(normalized)
            tmp_path = tmp.name
        try:
            booster = lgb.Booster(model_file=tmp_path)
        finally:
            os.unlink(tmp_path)
        return booster
    return lgb.Booster(model_file=str(model_path))


class FrozenModel:
    def __init__(self, model_dir: Path):
        self.name = model_dir.name
        self.booster = _load_booster_safe(model_dir / "booster.txt")

        with open(model_dir / "feature_names.json") as f:
            self.feature_names: list[str] = json.load(f)

        with open(model_dir / "categories.json") as f:
            self.categories: dict[str, list] = json.load(f)

        threshold_path = model_dir / "threshold.json"
        if threshold_path.exists():
            with open(threshold_path) as f:
                self.threshold: float = json.load(f).get("threshold", 0.5)
        else:
            self.threshold = 0.5

        # Guard: booster's internal feature list must match feature_names.json.
        # A mismatch means the model artifact and the schema file are out of sync.
        booster_features = self.booster.feature_name()
        if booster_features != self.feature_names:
            import logging
            logging.getLogger("model-loader").error(
                "SCHEMA MISMATCH in %s: booster has %d features, feature_names.json has %d. "
                "Scores may be wrong. Rebuild models after schema changes.",
                model_dir.name, len(booster_features), len(self.feature_names),
            )

    def predict_proba(self, row: dict) -> float:
        """Score a single feature dict. Returns probability of malicious class."""
        import pandas as pd
        from botsv2_parsers.parsers import NUMERIC_FEATURES

        df = pd.DataFrame([row], columns=self.feature_names)

        # Cast numeric columns explicitly to float64 so LightGBM doesn't
        # reject None-filled columns that pandas infers as 'object'.
        numeric_set = set(NUMERIC_FEATURES)
        for col in df.columns:
            if col in numeric_set:
                df[col] = pd.to_numeric(df[col], errors="coerce").astype("float64")

        # Align categorical columns to the training category set
        for col, cats in self.categories.items():
            if col in df.columns:
                df[col] = pd.Categorical(df[col], categories=cats)

        prob = self.booster.predict(df)[0]
        return float(prob)


def load_models(models_dir: Path) -> dict[str, FrozenModel]:
    """
    Load the honest production model.

    Final production model (2026-05-24, engineered-booleans approach):
    lgbm_xt_stratified_vanilla_engineered.

      Built by _engineered-features-retrain.py + 38 MITRE-derived
      boolean features in botsv2_parsers/engineered_features.py:
        - image_is_lolbin / shell / offensive_tool / parent_is_office / browser
        - target_in_temp / appdata / system32 / user_profile / unc_path
        - ext_is_ransomware / executable / document / double_suspicious
        - cmd_has_enc / iex / downloadstring / base64 / pipe_shell /
          hidden / bypass / noprofile / url / new_object / creddump /
          schtask_create / injection / log_clear / recon
        - target_run_key / services_imagepath / autorun_location
        - uri_has_sqli / xss / traversal / webshell

      Label = (sum(booleans) >= 2), so the AUC=1.0 reflects how perfectly
      the model approximates the hand-crafted rule. Test ROC-AUC is
      uninformative here — the meaningful metric is live-probe behaviour.

      Probe results at threshold 0.11:
        - 12/12 novel attack probes ALERT (incl. .locked/.encrypted/
          .pay2decrypt ransomware, CobaltStrike beacon.exe, Sliver implant,
          schtasks/certutil/regsvr32 LOLBin abuse, PowerShell -enc, mimikatz)
        - 5/7 benigns suppressed
        - 2 LOLBin FPs (legit PowerShell -Command, OneDrive .exe) — these
          score 0.999 regardless of threshold and require LLM disambiguation
        - 5/5 auditd / DNS / CONN OOD events correctly suppressed
    """
    models: dict[str, FrozenModel] = {}
    for name in ("lgbm_xt_stratified_vanilla_engineered",):
        model_dir = models_dir / name
        if not model_dir.exists():
            raise FileNotFoundError(f"Model directory not found: {model_dir}")
        models[name] = FrozenModel(model_dir)
    return models
