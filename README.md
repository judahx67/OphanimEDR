# Behavioral EDR Agent

ML-Enhanced Endpoint Detection and Response Agent for Windows

## Overview

A lightweight endpoint agent that monitors running processes in real-time, extracts behavioral features, and uses machine learning to detect potentially malicious activity.

## Project Structure

```
behavioral-edr/
├── agent/          # EDR Agent (deploys to Windows endpoints)
├── server/         # Management Server (Docker)
├── dashboard/      # Web UI (React)
├── shared/         # Shared code between agent & server
├── config/         # Centralized configuration
├── models/         # Trained ML models
├── notebooks/      # Jupyter notebooks for EDA
├── scripts/        # Utility scripts
├── tests/          # Test suite
└── docs/           # Documentation
```

## Quick Start

### Prerequisites
- Python 3.10+
- Windows 10/11 (for agent)
- Docker (for server)

### Development Setup

```bash
# Clone and setup
git clone <repo-url>
cd behavioral-edr

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -e ".[dev]"

# Run agent (development)
python -m edr_agent

# Run server (Docker)
docker-compose up
```

## Configuration

Set environment variables on each endpoint:
```powershell
[Environment]::SetEnvironmentVariable("SERVER_URL", "http://192.168.1.100:8000", "Machine")
[Environment]::SetEnvironmentVariable("AGENT_API_KEY", "your-key", "Machine")
```

## License

MIT
