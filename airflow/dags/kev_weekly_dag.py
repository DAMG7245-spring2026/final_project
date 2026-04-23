"""
KEV weekly sync (DAG): every Sunday 05:30 UTC, fetch the CISA Known Exploited
Vulnerabilities catalog and enrich Snowflake ``cve_records`` in place — set
``is_kev = TRUE`` plus the KEV columns (date added, required action, due date,
ransomware use, vendor/product). KEV entries whose ``cve_id`` is not yet in
``cve_records`` are parked in ``kev_pending_fetch`` for later NVD backfill.

Runs after ``nvd_weekly_delta_dag`` (05:00 UTC) so the MERGE sees the latest
CVE rows. Re-running is idempotent — the KEV feed is a full snapshot and the
enricher MERGEs on ``cve_id``.

Single task: ``ingestion.kev.enricher.run_kev_sync`` already does fetch +
dedupe + Snowflake stage/COPY/MERGE end-to-end.

Requires Snowflake creds in env.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pendulum
from airflow import DAG
from airflow.operators.python import PythonOperator

# Make the repo root importable so ``ingestion.*`` resolves at DAG parse time.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


default_args = {
    "owner": "cti",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
}


def run_kev_weekly(**context) -> dict:
    from ingestion.kev.enricher import run_kev_sync

    stats = run_kev_sync()
    context["ti"].log.info("KEV weekly sync: %s", stats)
    return stats


with DAG(
    dag_id="kev_weekly_dag",
    default_args=default_args,
    description="CISA KEV catalog → Snowflake cve_records enrichment + kev_pending_fetch queue.",
    schedule="30 5 * * 0",
    start_date=pendulum.datetime(2026, 4, 1, tz="UTC"),
    catchup=False,
    tags=["kev", "cisa", "weekly", "snowflake", "ingest"],
    doc_md=__doc__,
) as dag:
    sync_kev = PythonOperator(
        task_id="run_kev_sync",
        python_callable=run_kev_weekly,
    )
