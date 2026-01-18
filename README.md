# Ophanim EDR

ML-Enhanced Endpoint Detection and Response for Windows

## Overview

A lightweight endpoint agent that monitors system activity in real-time, extracts behavioral features, and uses machine learning to detect malicious activity.

## Project Structure

```
ophanim-edr/
├── agent/          # Windows EDR Agent (Python)
├── server/         # FastAPI Backend (Docker)
├── dashboard/      # React Dashboard (Fluent UI)
├── docs/           # Documentation
└── docker-compose.yml
```

## Quick Start

### Prerequisites
- Python 3.13+ (agent)
- Docker & Docker Compose (server/dashboard)
- Windows 10/11 (for agent deployment)

### Development

```bash
# Clone repository
git clone <repo-url>
cd ophanim-edr

# Option 1: Hot-reload development (recommended)
docker compose -f docker-compose.dev.yml up

# Option 2: Production build
docker compose up --build

# Seed demo data
curl -X POST http://localhost:8000/api/seed
```

**Access:**
- Dashboard: http://localhost:3000
- API Docs: http://localhost:8000/docs

### Agent Setup (Windows)

```powershell
# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate

# Install dependencies
pip install -e ".[dev]"

# Configure server URL
$env:SERVER_URL = "http://192.168.1.100:8000"

# Run agent
python -m edr_agent
```

## Docker Compose Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Production build (nginx frontend) |
| `docker-compose.dev.yml` | Development with hot-reload |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_URL` | `http://localhost:8000` | Backend API URL |
| `MONGODB_URL` | `mongodb://localhost:27017` | MongoDB connection |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## License

MIT
