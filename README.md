# CTI Platform

## Prerequisites

- Python 3.11+
- [Poetry](https://python-poetry.org/docs/#installation)
- Docker & Docker Compose
- Snowflake account
- Redis (local or Docker)


## Running Locally

```bash
# Install dependencies
poetry install

# Start Redis
docker run -d --name redis-local -p 6379:6379 redis:7-alpine


# Start the server
poetry run uvicorn app.main:app --reload --port 8000
```

API docs available at `http://localhost:8000/docs`

## Running with Docker

```bash
docker compose -f docker/docker-compose.yml --env-file .env up --build
```


## Health Check

```bash
curl http://localhost:8000/health
```
