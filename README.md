# Ophanim EDR - Behavioral Malware Detection System

**Thesis Project**: Machine learning-based endpoint detection and response system for behavioral threat analysis.

---

## Project Structure

```
THESIS-EDR/
├── agent/               # EDR Agent (Windows endpoint monitoring)
│   └── src/edr_agent/   # Process, network, file collectors
│
├── server/              # Server & Dashboard
│   ├── api/             # FastAPI backend
│   ├── dashboard/       # React frontend
│   └── docker-compose*.yml
│
├── scripts/             # Build & deployment scripts
├── docs/                # Documentation
└── .env                 # Centralized configuration
```

---

## Quick Start

### 1. Development (Hot Reload)

From `server/` directory:

```bash
# Start backend + dashboard + MongoDB
docker compose -f docker-compose.dev.yml up
```

- Dashboard: http://localhost:3000
- API: http://localhost:8000/docs

### 2. Agent (Windows Only)

From `agent/src/` directory:

```bash
# Configure
cp ../../.env.example ../../.env
# Edit .env with your settings

# Run agent
python -m edr_agent
```

---

## Configuration

All settings are centralized in **root `.env`** file:

- **Agent**: Authentication, collectors, logging
- **Server**: MongoDB connection, API settings

See `.env.example` for all options.

---

## Components

| Component | Purpose | Tech Stack |
|-----------|---------|------------|
| **Agent** | Endpoint telemetry collection | Python, psutil, watchdog, Sysmon |
| **API** | Event ingestion & detection engine | FastAPI, MongoDB, Motor |
| **Dashboard** | Security operations interface | React, TypeScript, Recharts |

---

## Documentation

- [Agent Architecture](./agent/README.md)
- [Server API](./server/api/README.md)
- [Dashboard](./server/dashboard/README.md)
- [Progress Tracking](./PROGRESS.md)

---

## Development

- **Dataset Alignment**: LANL (auth/lateral movement), BETH (process/kernel)
- **Next Phase**: Authentication logging, ETW integration, PowerShell monitoring
