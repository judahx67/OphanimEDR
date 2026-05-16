FROM python:3.13-slim

WORKDIR /app

# LightGBM needs libgomp; supervisord orchestrates the 4 workers.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
        supervisor \
    && rm -rf /var/lib/apt/lists/*

COPY pipeline/requirements.txt /app/pipeline/requirements.txt
RUN pip install --no-cache-dir -r /app/pipeline/requirements.txt

# Shared package — importable from every worker via PYTHONPATH=/app
COPY botsv2_parsers/ /app/botsv2_parsers/

# Worker source trees (each preserves its own CWD layout)
COPY ingest/         /app/ingest/
COPY graph-builder/  /app/graph-builder/
COPY rule-engine/    /app/rule-engine/
COPY ml-edge-scorer/ /app/ml-edge-scorer/

COPY pipeline/supervisord.conf /app/pipeline/supervisord.conf

ENV PYTHONPATH=/app PYTHONUNBUFFERED=1

CMD ["supervisord", "-c", "/app/pipeline/supervisord.conf", "-n"]
