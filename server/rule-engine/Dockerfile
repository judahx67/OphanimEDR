FROM python:3.13-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "pika>=1.3.2" \
    "neo4j>=5.18.0" \
    "pydantic>=2.5.0" \
    "pyyaml>=6.0"

COPY loader.py engine.py main.py ./
COPY rules/ ./rules/

CMD ["python", "main.py"]
