FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    "fastapi>=0.109.0" \
    "uvicorn[standard]>=0.27.0" \
    "neo4j>=5.18.0" \
    "pydantic>=2.5.0" \
    "httpx>=0.26.0" \
    "pyyaml>=6.0" \
    "google-genai>=1.0.0" \
    "groq>=0.11.0" \
    "openai>=1.40.0" \
    "anthropic>=0.40.0"

COPY edr_server ./edr_server

EXPOSE 8000
CMD ["uvicorn", "edr_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
