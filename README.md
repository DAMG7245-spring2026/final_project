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
4. `07_ingestion_monitoring.sql` — `ingestion_checkpoints`, `pipeline_runs` Airflow columns, `cve_records.kev_neo4j_dirty`, extended `kev_pending_fetch` KEV columns

To apply the same DDL from the CLI using `.env` credentials: `poetry run python scripts/push_snowflake_ddl.py`.  
To apply **only** monitoring objects for Airflow (`ingestion_checkpoints`, `pipeline_runs` columns, etc.) when the rest of the warehouse is already deployed: `poetry run python scripts/apply_ingestion_monitoring.py` (then run the printed `GRANT` statements in Snowflake if the Airflow user gets “not authorized”).

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

#### Airflow: structured ingestion and Neo4j

**NVD S3 batch (historical months):** three manual DAGs. The inclusive month window defaults to **2023-01 … 2023-12** in [`airflow/dags/lib/nvd_months.py`](airflow/dags/lib/nvd_months.py). Override **without editing code** using, in order: environment **`CTI_NVD_YM_START`** / **`CTI_NVD_YM_END`** (`YYYY-MM`), or Airflow Variables **`NVD_BATCH_YM_START`** / **`NVD_BATCH_YM_END`**. S3 layout: **`s3://$S3_BUCKET/nvd/raw/YYYY-MM.jsonl`** and **`s3://$S3_BUCKET/nvd/curated/YYYY-MM.ndjson`**.

| DAG | File | What it does |
|-----|------|----------------|
| **`nvd_fetch_dag`** | [`airflow/dags/nvd_fetch_dag.py`](airflow/dags/nvd_fetch_dag.py) | **NVD API → S3 raw only.** One mapped task per month in the window. Then triggers `nvd_transform_dag` with `wait_for_completion=True`. |
| **`nvd_transform_dag`** | [`airflow/dags/nvd_transform_dag.py`](airflow/dags/nvd_transform_dag.py) | **`schedule=None`.** Raw `*.jsonl` → curated `*.ndjson` on S3. Then triggers `nvd_load_dag`. |
| **`nvd_load_dag`** | [`airflow/dags/nvd_load_dag.py`](airflow/dags/nvd_load_dag.py) | **`schedule=None`.** Curated NDJSON → Snowflake **`cve_records`** (MERGE). |
| **`nvd_incremental_dag`** | [`airflow/dags/nvd_incremental_dag.py`](airflow/dags/nvd_incremental_dag.py) | **NVD API → Snowflake** via `sync_delta` in **sequential** day slices (default **7** days; override with `conf.slice_days`). Each trigger resolves **`start`/`end`** from: optional `conf.force_start` / `force_end`, else **`ingestion_checkpoints`** row `nvd_api_last_modified_through`, else **`DATE(MAX(last_modified))`** from `cve_records`, with **`end`** = today UTC. Advances the checkpoint **after each successful slice**. |
| **`nvd_s3_slice_pipeline_dag`** | [`airflow/dags/nvd_s3_slice_pipeline_dag.py`](airflow/dags/nvd_s3_slice_pipeline_dag.py) | Same window and **`conf.slice_days`** chunking as **`nvd_incremental_dag`**, with **three chained mapped stages per slice** — **`fetch_slice`** → **`transform_slice`** → **`load_slice`** — to **`{prefix}/raw/slices/…`**, **`{prefix}/curated/slices/…`**, then Snowflake. Slices still run **in parallel within each stage** (same API granularity per fetch). Uses checkpoint **`nvd_s3_slice_pipeline_through`** (not **`nvd_api_last_modified_through`**). Coexists with calendar-month **`nvd_*`** batch DAGs; overlap with **`nvd_incremental_dag`** **MERGE**s safely but repeats NVD API calls. |
| **`kev_sync_dag`** | [`airflow/dags/kev_sync_dag.py`](airflow/dags/kev_sync_dag.py) | **`fetch_and_enrich` → `resolve_pending` → `sync_kev_neo4j`**: CISA KEV → Snowflake, drain **`kev_pending_fetch`** via **`sync_single_cve`**, then targeted Neo4j **`(:CVE)`** KEV props. |
| **`cwe_catalog_dag`** | [`airflow/dags/cwe_catalog_dag.py`](airflow/dags/cwe_catalog_dag.py) | Manual bulk CWE load; set **`conf.catalog_path`** or Airflow Variable **`CWE_CATALOG_PATH`**. |
| **`neo4j_structured_sync_dag`** | [`airflow/dags/neo4j_structured_sync_dag.py`](airflow/dags/neo4j_structured_sync_dag.py) | **`cve_cwe_kev_sync` → `attack_techniques_sync` → `chunk_technique_links_sync`** (full structured graph catch-up using `loaded_to_neo4j`). |
| **`attack_weekly_dag`** | [`airflow/dags/attack_weekly_dag.py`](airflow/dags/attack_weekly_dag.py) | MITRE ATT&CK full reload into Snowflake (weekly schedule). |

**`pipeline_runs`:** DAG tasks call [`ingestion/monitoring/snowflake_runs.py`](ingestion/monitoring/snowflake_runs.py) (`start_pipeline_run` / `complete_pipeline_run`) for an audit row per logical step (requires **`07_ingestion_monitoring.sql`** applied).

**NVD batch flow:** trigger **`nvd_fetch_dag`** (or transform/load only for replays). **Incremental NVD (direct Snowflake):** trigger **`nvd_incremental_dag`**. **Incremental NVD (S3 + parallel slices):** trigger **`nvd_s3_slice_pipeline_dag`** (optional `conf.prefix`, same `force_start` / `force_end` / `slice_days`). Optional backfill example: `{"force_start": "2024-01-01", "force_end": "2024-01-31"}`.

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

## CTI knowledge graph API (FastAPI)

Structured routes read from **Neo4j** (CVE/CWE sync, ATT&CK techniques, chunk-derived `REFERENCES_TECHNIQUE` edges, and native ATT&CK nodes/relationships where loaded). Hybrid and vector search stay under **`/search/...`** (Snowflake `advisory_chunks`).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Snowflake, Redis, S3, Neo4j connectivity (200 only if all healthy). |
| GET | `/cve/{cve_id}` | `:CVE` properties plus `HAS_WEAKNESS`→CWE and `REFERENCES_TECHNIQUE`→Technique rows. |
| GET | `/actor/{actor_id}` | `:Actor` matched by `name`, `actor_id`, `id`, or `external_id`, plus bounded neighborhood. |
| GET | `/technique/{technique_id}` | `:Technique` by MITRE id (e.g. `T1059`), plus bounded neighborhood. |
| GET | `/graph/attack-path` | Query params: **exactly one** of `from_cve`, `from_actor`, `from_technique`; optional `max_hops` (1–6), `limit` (1–25). |
| POST | `/query` | **Stub** — returns `{ "status": "pending", "message": "..." }` until unstructured advisory data is in Neo4j. |
| GET | `/brief/weekly` | **Stub** — same pending payload until advisory graph narrative is wired. |

Examples:

```bash
curl -s "http://localhost:8000/cve/CVE-2024-21413"
curl -s "http://localhost:8000/technique/T1059"
curl -s "http://localhost:8000/graph/attack-path?from_cve=CVE-2024-21413&max_hops=3&limit=5"
curl -s -X POST "http://localhost:8000/query" -H "Content-Type: application/json" -d '{"query":"test"}'
curl -s "http://localhost:8000/brief/weekly"
```

## Streamlit CTI console

Multipage UI under [`streamlit_cti/`](streamlit_cti/) that calls the same FastAPI endpoints (sidebar **API base URL**; optional **`CTI_API_BASE`** in `.env` for the default).

**Prerequisites:** API running (`poetry run uvicorn app.main:app --reload --port 8000`). Hybrid search needs the API to have finished BM25 startup; graph pages need Neo4j healthy.

```bash
poetry run streamlit run streamlit_cti/Home.py --server.port 8501
```

Open `http://localhost:8501` and use the sidebar pages (Health, CVE, Actor, …). On **Home**, use **Ping API** to confirm the UI reaches the backend.

**Docker (API + Streamlit together):** from `docker/`, `docker compose up --build` starts the API on port 8000 and **cti-ui** (Streamlit) on **8501** with `CTI_API_BASE=http://api:8000` so the console talks to the API over the Compose network.

## Health Check

```bash
curl http://localhost:8000/health
```
