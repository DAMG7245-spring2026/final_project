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

### CWE catalog (Phase 5 — review before Snowflake)

1. **Fetch official CWE v4.16** into `data/` (downloads the XML zip from MITRE, unzips, writes `data/cwec_catalog.json` in the shape `cwe_catalog.py` expects):

   ```bash
   poetry run python scripts/fetch_cwe_catalog.py
   # If you already have data/cwec_v4.16.xml.zip locally:
   poetry run python scripts/fetch_cwe_catalog.py --skip-download
   ```

   Alternatively, supply your own catalog JSON with a top-level `weaknesses` array (objects with `CWE_ID`, `Name`, `Abstraction`, `Status`, `Description`). MITRE lists downloads at [CWE downloads](https://cwe.mitre.org/data/downloads.html).

2. **Preview only** (no database writes) — writes transformed rows (matching `cwe_records`) and prints counts:

   ```bash
   poetry run python scripts/cwe_catalog.py preview data/cwec_catalog.json --out-dir data
   # same as above: files go to <project>/data/ by default. Or: ... preview YOUR.json --out-dir data
   ```

   Optional: `--limit N`, `--format ndjson`. By default also writes **`data/cwe_raw_sample.json`**: the first **10** items from the source `weaknesses` array (untransformed) so you can compare with `cwe_transformed_preview.json`. Use `--skip-raw-sample` to turn that off, or `--raw-sample-limit` / `--raw-sample-out` to adjust.

3. After you review the file, **load into Snowflake** (requires `.env` Snowflake vars):

   ```bash
   poetry run python scripts/cwe_catalog.py load-snowflake --input data/cwec_catalog.json
   ```

   Or load exactly what you saved: `load-snowflake --from-transformed data/cwe_transformed_preview.json`.

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
