FROM python:3.13-slim

WORKDIR /app

# LightGBM requires libgomp (OpenMP runtime)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY ml-edge-scorer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Shared parsers package
COPY botsv2_parsers/ ./botsv2_parsers/

# Service code
COPY ml-edge-scorer/ .

CMD ["python", "main.py"]
