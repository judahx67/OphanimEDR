# Ophanim EDR - Server API

FastAPI backend for event ingestion, detection processing, and security analytics.

## Structure

```
api/
├── edr_server/
│   ├── main.py         # FastAPI application
│   ├── models.py       # Pydantic schemas
│   └── database.py     # MongoDB connection
├── Dockerfile
├── manage.py           # Database management CLI
└── pyproject.toml
```

## Development

```bash
# From server/ directory
docker compose -f docker-compose.dev.yml up backend

# Or run locally:
cd api
uvicorn edr_server.main:app --reload
```

## API Endpoints

- `GET /api/health` - Health check
- `POST /api/endpoints` - Register agent
- `POST /api/events` - Ingest events
- `GET /api/detections` - Query detections
- `POST /api/seed` - Generate demo data

Full docs: http://localhost:8000/docs

## Database Management

```bash
# Seed demo data
python manage.py seed

# Clear all data
python manage.py clear
```

## Environment Variables

All settings loaded from `../../.env`:

- `MONGODB_URL` - MongoDB connection string
- `DATABASE_NAME` - Database name
- `SERVER_URL` - Public server URL
