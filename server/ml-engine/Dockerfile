FROM python:3.13-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "neo4j>=5.18.0" \
    "xgboost>=2.0.3" \
    "scikit-learn>=1.4.0" \
    "numpy>=1.26.0"

COPY feature_extractor.py trainer.py main.py ./

CMD ["python", "main.py"]
