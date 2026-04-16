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

### NVD CVE ingestion (Phase 2)

Ingest from the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) into **`cve_records`** (MERGE upsert; KEV columns are left unchanged on update).

**Rate limits:** without **`NVD_API_KEY`**, the client waits **~6 seconds** between paginated requests (5 req / 30s). With a key, **~0.65 seconds** (50 req / 30s). Optional **`NVD_MIN_REQUEST_INTERVAL_SEC`** in `.env` overrides both (you must stay within NVD policy).

**Staging:** use local paths under `data/nvd/raw/` and `data/nvd/curated/`, or **`s3://$S3_BUCKET/nvd/...`** for any of `--raw-out`, `--raw-in`, `--curated-out`, `--curated-in` (requires **`AWS_ACCESS_KEY_ID`**, **`AWS_SECRET_ACCESS_KEY`**, **`AWS_REGION`**, **`S3_BUCKET`** in `.env`, or instance credentials).

Fetch/transform write **temporary files on the worker** when the destination is S3 (full raw month, then upload; curated NDJSON to a temp file, then upload). Transform can **stream** raw from S3 line-by-line when the source is `s3://`.

```bash
# 1) Fetch raw NDJSON (lastModified in range; inclusive dates)
poetry run python scripts/nvd_ingest.py fetch --start 2024-01-01 --end 2024-01-07 \
  --raw-out data/nvd/raw/2024-01.jsonl

# Same flow with S3 raw object (temp local .jsonl during fetch, then put_object)
# poetry run python scripts/nvd_ingest.py fetch --start 2024-01-01 --end 2024-01-07 \
#   --raw-out s3://your-bucket/nvd/raw/2024-01.jsonl

poetry run python scripts/nvd_ingest.py fetch --cve CVE-2024-21413 --raw-out data/nvd/raw/cve.jsonl

# 2) Transform to curated NDJSON
poetry run python scripts/nvd_ingest.py transform --raw-in data/nvd/raw/2024-01.jsonl \
  --curated-out data/nvd/curated/2024-01.ndjson

# 3) Load curated file to Snowflake (batched reads; requires Snowflake .env vars)
poetry run python scripts/nvd_ingest.py load --curated-in data/nvd/curated/2024-01.ndjson --batch-size 2000
# poetry run python scripts/nvd_ingest.py load \
#   --curated-in s3://your-bucket/nvd/curated/2024-01.ndjson --batch-size 2000
```

**One-shot (in-memory, small windows):**

```bash
poetry run python scripts/nvd_ingest.py sync --start 2024-01-01 --end 2024-01-07
poetry run python scripts/nvd_ingest.py sync --cve CVE-2024-21413
poetry run python scripts/nvd_ingest.py sync --start 2024-01-01 --end 2024-01-02 --dry-run
```

Programmatic use: `from ingestion.nvd.pipeline import sync_delta, sync_single_cve`, `load_curated_file_to_snowflake`, `transform_raw_file_to_curated`, `fetch_delta_to_raw_file`, `ingest_lastmod_month_to_disk_and_snowflake`, `ingest_lastmod_month_to_s3_and_snowflake`.

#### Airflow: NVD three-stage batch (calendar year 2020)

NVD backfill is split into **three manual DAGs** (no calendar schedule on the pipeline itself). Month window **2020-01 … 2020-12** (12 months) is defined in [`airflow/dags/lib/nvd_months.py`](airflow/dags/lib/nvd_months.py) (`NVD_YM_START` / `NVD_YM_END`); widen `NVD_YM_END` there to include more years later. S3 layout: **`s3://$S3_BUCKET/nvd/raw/YYYY-MM.jsonl`** and **`s3://$S3_BUCKET/nvd/curated/YYYY-MM.ndjson`**.

| DAG | File | What it does |
|-----|------|----------------|
| **`nvd_fetch_dag`** | [`airflow/dags/nvd_fetch_dag.py`](airflow/dags/nvd_fetch_dag.py) | **NVD API → S3 raw only.** Dynamic task mapping: one task per month. On **all successes**, triggers `nvd_transform_dag` with `wait_for_completion=True`. |
| **`nvd_transform_dag`** | [`airflow/dags/nvd_transform_dag.py`](airflow/dags/nvd_transform_dag.py) | **`schedule=None`.** Lists raw `*.jsonl` under `nvd/raw/`, transforms each to curated on S3 (**no NVD API**). Then triggers `nvd_load_dag` with `wait_for_completion=True`. |
| **`nvd_load_dag`** | [`airflow/dags/nvd_load_dag.py`](airflow/dags/nvd_load_dag.py) | **`schedule=None`.** Lists `nvd/curated/*.ndjson` in window, **MERGE**s each into **`cve_records`** (batch size **2000**). Safe to re-run without NVD. |

**Flow:** unpause or trigger **`nvd_fetch_dag`** once. It runs fetch tasks, then chains transform and load via **`TriggerDagRunOperator`**. To **re-transform** after a code fix, trigger **`nvd_transform_dag`** only (raw already on S3). To **re-load Snowflake** only, trigger **`nvd_load_dag`**.

Install Airflow in a **separate** venv from the app (see [`airflow/requirements.txt`](airflow/requirements.txt)), or use **Docker** (below). On the worker:

- Set **`PYTHONPATH`** to this repo root (so `import ingestion` / `import app` work).
- Optional **`CTI_PROJECT_ROOT`**: absolute path to the repo if needed (see [`.env.example`](.env.example)).
- Provide **Snowflake** credentials, **`S3_BUCKET`**, **AWS** credentials (or IAM role), and **`NVD_API_KEY`** (strongly recommended when many months fetch in parallel). Optional **`NVD_MIN_REQUEST_INTERVAL_SEC`**.

**Airflow via Docker (UI + scheduler):** [`docker/docker-compose.airflow.yml`](docker/docker-compose.airflow.yml) (Postgres metadata, LocalExecutor). The small custom [`docker/airflow/Dockerfile`](docker/airflow/Dockerfile) extends `apache/airflow:2.8.3-python3.11` and bakes in DAG runtime deps from [`docker/airflow/requirements-dag-runtime.txt`](docker/airflow/requirements-dag-runtime.txt) (Pydantic, `httpx`, **`boto3`**, etc.) so task imports of `app` / `ingestion` work without slow per-start `pip` installs (unlike `_PIP_ADDITIONAL_REQUIREMENTS` on the stock image alone).

1. **`AIRFLOW_FERNET_KEY`** in `.env` is **optional** for local testing: the compose file supplies a **committed dev-only default** (not secret—anyone with the repo can decrypt Airflow-stored connection payloads if you use the UI to save passwords). Override with your own key for anything beyond solo local use (see [`.env.example`](.env.example)).
2. From the **repo root** (use `--env-file .env` so Snowflake / **`NVD_API_KEY`** reach the containers when you run the DAG):

   ```bash
   docker compose --env-file .env -f docker/docker-compose.airflow.yml up --build -d
   ```

3. Open **`http://localhost:8080`**. Default login **`airflow` / `airflow`** (created once by `airflow-init`; change in production).
4. **Unpause** DAGs **`nvd_fetch_dag`**, **`nvd_transform_dag`**, and **`nvd_load_dag`** (or leave transform/load paused until fetch completes). **Trigger `nvd_fetch_dag`** to start a full batch; expect long runtime and heavy NVD API use without **`NVD_API_KEY`**.
5. **`wait_for_completion=True`** on triggers holds the upstream DAG’s worker until the child DAG finishes (LocalExecutor: one worker slot for a long time). For very long runs, consider async trigger + sensors later.
6. **Linux:** set **`AIRFLOW_UID`** in `.env` to your host `id -u` if bind-mounted volumes need matching ownership.

**Local-only monthly ingest** (no S3): call `ingest_lastmod_month_to_disk_and_snowflake` from a one-off script or REPL with a `base_dir` under `data/nvd/`.

**Note:** Full fetch can take a long time; workers need temp disk for fetch/upload when using S3. Re-runs are safe (Snowflake **MERGE** is idempotent on `cve_id`). If any **fetch** mapped task fails, the transform trigger does **not** run (`all_success` upstream).

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

   Programmatic API (report Task 5.1): `from ingestion.cwe.loader import load_cwe_records` then `load_cwe_records("data/cwec_catalog.json")`.

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

The API stack does not include Airflow; use [`docker/docker-compose.airflow.yml`](docker/docker-compose.airflow.yml) for the NVD three-stage DAGs (see **Airflow via Docker** under [NVD CVE ingestion](#nvd-cve-ingestion-phase-2)).

## Health Check

```bash
curl http://localhost:8000/health
```
