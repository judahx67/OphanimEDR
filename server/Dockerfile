# EDR Server Dockerfile
FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY server/pyproject.toml ./
RUN pip install --no-cache-dir fastapi uvicorn motor pydantic python-dotenv

# Copy source code
COPY server/src ./src

# Expose port
EXPOSE 8000

# Set Python path
ENV PYTHONPATH=/app/src

# Run server
CMD ["uvicorn", "edr_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
