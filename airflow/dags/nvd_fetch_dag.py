"""
NVD batch fetch (DAG 1): one mapped task per calendar month (2020-01 .. 2020-12),
each writes raw NDJSON to S3 only (no transform, no Snowflake).

After all fetch tasks succeed, triggers ``nvd_transform_dag`` with ``wait_for_completion=True``.

Manual trigger only (``schedule=None``). Requires ``S3_BUCKET``, ``NVD_API_KEY``, AWS creds in .env.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pendulum
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.trigger_dagrun import TriggerDagRunOperator

_DAG_DIR = Path(__file__).resolve().parent
if str(_DAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DAG_DIR))

from lib.nvd_months import (  # noqa: E402
    NVD_BATCH_MONTH_ARGS,
    ensure_repo_imports,
    first_last_day,
    raw_s3_uri,
)

default_args = {
    "owner": "cti",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=12),
}


def fetch_one_month(year: int, month: int, **context) -> dict:
    ensure_repo_imports()
    from app.config import get_settings
    from ingestion.nvd.pipeline import fetch_delta_to_raw_file

    b = (get_settings().s3_bucket or "").strip()
    if not b:
        raise ValueError("S3_BUCKET not set in environment.")
    prefix = "nvd"
    start, end = first_last_day(year, month)
    raw_uri = raw_s3_uri(b, prefix, year, month)
    stats = fetch_delta_to_raw_file(start, end, raw_uri)
    context["ti"].log.info("NVD fetch %04d-%02d: %s", year, month, stats)
    return {"year": year, "month": month, "fetch": stats, "raw_uri": raw_uri}


with DAG(
    dag_id="nvd_fetch_dag",
    default_args=default_args,
    description="NVD API → S3 raw only (all months); then trigger transform DAG.",
    schedule=None,
    start_date=pendulum.datetime(2020, 1, 1, tz="UTC"),
    catchup=False,
    tags=["nvd", "s3", "fetch", "ingest"],
    doc_md=__doc__,
) as dag:
    fetch_tasks = PythonOperator.partial(
        task_id="fetch_to_s3",
        python_callable=fetch_one_month,
    ).expand(op_args=NVD_BATCH_MONTH_ARGS)

    trigger_transform = TriggerDagRunOperator(
        task_id="trigger_transform",
        trigger_dag_id="nvd_transform_dag",
        wait_for_completion=True,
        conf={"prefix": "nvd"},
    )

    fetch_tasks >> trigger_transform
