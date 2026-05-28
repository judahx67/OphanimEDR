FROM python:3.13-slim

WORKDIR /app

# build-essential covers any source builds (gensim/scipy) on cp313.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# theia_flash_common + trained_weights are mounted at /app/theia (see compose).
ENTRYPOINT ["python", "-u", "main.py"]
