FROM python:3.13-slim

WORKDIR /app

COPY ingest/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Shared parsers package (needed for BOTSv2 ingest mode)
COPY botsv2_parsers/ ./botsv2_parsers/

# Service code
COPY ingest/ .

CMD ["python", "main.py"]
