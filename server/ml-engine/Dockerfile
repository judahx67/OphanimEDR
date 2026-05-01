FROM python:3.11-slim

# AutoGluon needs build tools for some wheels (lightgbm, xgboost) and libgomp.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libgomp1 \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# AutoGluon Tabular pulls a heavy ML stack (lightgbm, xgboost, catboost,
# scikit-learn, torch). The slim variant of `autogluon.tabular` is enough
# for our use case and skips the vision/text extras.
RUN pip install --no-cache-dir \
        "neo4j>=5.18.0" \
        "pyyaml>=6.0" \
        "pandas>=2.0.0" \
        "typing_extensions>=4.10.0" \
        "autogluon.tabular[lightgbm,xgboost,catboost]>=1.1.0"

COPY feature_extractor.py trainer.py main.py ./

# Rules directory mounted from the rule-engine service so we can read
# tactic tags from each rule's YAML.
RUN mkdir -p /app/rules

CMD ["python", "main.py"]
