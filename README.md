# CTI Platform

## Prerequisites

- Python 3.11+
- [Poetry](https://python-poetry.org/docs/#installation)
- Docker & Docker Compose
- Snowflake account
- Redis (local or Docker)

## Snowflake layout (core CTI in PUBLIC, no CISA advisory DDL here)

Idempotent DDL lives in [`snowflake/sql/`](snowflake/sql/). Run in order in a worksheet (role needs `CREATE TABLE` on `CTI_PLATFORM_DATABASE.PUBLIC` and permission to drop schemas if migrating off CURATED):

1. `01_schemas.sql` — drops `CURATED` / `AGENT` / `MONITOR` if present, then `USE SCHEMA PUBLIC`
2. `02_curated_core.sql` — `cve_records`, CWE/KEV queue, ATT&CK tables in **PUBLIC**
3. `03_monitor.sql` — `pipeline_runs` in **PUBLIC**

To apply the same DDL from the CLI using `.env` credentials: `poetry run python scripts/push_snowflake_ddl.py`.

**Environment:** set `SNOWFLAKE_DATABASE=CTI_PLATFORM_DATABASE` and `SNOWFLAKE_SCHEMA=PUBLIC`. Core CTI tables and existing advisory tables (`ADVISORIES`, `ADVISORY_CHUNKS`, `ALEMBIC_VERSION`) live under **PUBLIC**.

**Alembic:** revision `992c03d4f851` targets the schema in `SNOWFLAKE_SCHEMA` (use `PUBLIC` to match the layout above).

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
