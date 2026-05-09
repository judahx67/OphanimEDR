FROM python:3.13-slim

WORKDIR /app

COPY llm-analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY llm-analyzer/ .

CMD ["python", "main.py"]
