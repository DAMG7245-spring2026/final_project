"""
NVD weekly delta (DAG): every Sunday 05:00 UTC, fetch CVEs modified in the past
7 days, transform to curated NDJSON on S3, MERGE into Snowflake ``cve_records``
and ``cve_cwe_mappings``. Single end-to-end DAG (not the 3-DAG chain used for
historical backfill) because a 7-day delta is small enough to fetch/transform/load
in one run.

Window comes from Airflow's ``data_interval_start`` / ``data_interval_end`` so
it's exactly the scheduled 7-day slice — reruns and backfills get the right
window automatically.

S3 paths:
  s3://$S3_BUCKET/nvd/weekly/raw/<YYYY>-W<WW>.jsonl
  s3://$S3_BUCKET/nvd/weekly/curated/<YYYY>-W<WW>.ndjson

Requires ``S3_BUCKET``, ``NVD_API_KEY`` (recommended), AWS creds in env.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pendulum
from airflow.decorators import dag, task

# Make the repo root importable so ``app.*`` / ``ingestion.*`` resolve when the
# scheduler parses this file. Two levels up from airflow/dags/ → repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


default_args = {
    "owner": "cti",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=10),
}


def _week_tag(end_dt: pendulum.DateTime) -> str:
    # ISO week-year + ISO week number, e.g. "2026-W17".
    return end_dt.strftime("%G-W%V")


def _s3_uris(bucket: str, tag: str) -> tuple[str, str]:
    raw = f"s3://{bucket}/nvd/weekly/raw/{tag}.jsonl"
    curated = f"s3://{bucket}/nvd/weekly/curated/{tag}.ndjson"
    return raw, curated


@dag(
    dag_id="nvd_weekly_delta_dag",
    default_args=default_args,
    description="NVD lastModified past-7-days delta → S3 raw/curated → Snowflake MERGE.",
    schedule="0 5 * * 0",
    start_date=pendulum.datetime(2026, 4, 1, tz="UTC"),
    catchup=False,
    tags=["nvd", "weekly", "delta", "snowflake", "ingest"],
    doc_md=__doc__,
)
def build_nvd_weekly_delta_dag():
    @task(task_id="fetch_delta_to_s3")
    def fetch_delta_to_s3(**context) -> dict:
        from app.config import get_settings
        from ingestion.nvd.pipeline import fetch_delta_to_raw_file

        bucket = (get_settings().s3_bucket or "").strip()
        if not bucket:
            raise ValueError("S3_BUCKET not set in environment.")

        start_dt: pendulum.DateTime = context["data_interval_start"]
        end_dt: pendulum.DateTime = context["data_interval_end"]
        tag = _week_tag(end_dt)
        raw_uri, _ = _s3_uris(bucket, tag)

        stats = fetch_delta_to_raw_file(start_dt.date(), end_dt.date(), raw_uri)
        context["ti"].log.info(
            "NVD weekly delta fetch %s (%s → %s): %s",
            tag,
            start_dt.date(),
            end_dt.date(),
            stats,
        )
        return {"tag": tag, "raw_uri": raw_uri, "fetch": stats}

    @task(task_id="transform_to_curated")
    def transform_to_curated(fetch_result: dict, **context) -> dict:
        from app.config import get_settings
        from ingestion.nvd.pipeline import transform_raw_file_to_curated

        bucket = (get_settings().s3_bucket or "").strip()
        if not bucket:
            raise ValueError("S3_BUCKET not set in environment.")

        tag = fetch_result["tag"]
        raw_uri, curated_uri = _s3_uris(bucket, tag)
        stats = transform_raw_file_to_curated(raw_uri, curated_uri)
        context["ti"].log.info(
            "NVD weekly delta transform %s → %s: %s", raw_uri, curated_uri, stats
        )
        return {"tag": tag, "curated_uri": curated_uri, "transform": stats}

    @task(task_id="load_to_snowflake")
    def load_to_snowflake(transform_result: dict, **context) -> dict:
        from ingestion.nvd.pipeline import load_curated_file_to_snowflake

        curated_uri = transform_result["curated_uri"]
        stats = load_curated_file_to_snowflake(curated_uri, batch_size=2000)
        context["ti"].log.info(
            "NVD weekly delta load %s: %s", curated_uri, stats
        )
        return {
            "tag": transform_result["tag"],
            "curated_uri": curated_uri,
            "load": stats,
        }

    load_to_snowflake(transform_to_curated(fetch_delta_to_s3()))


nvd_weekly_delta_dag = build_nvd_weekly_delta_dag()
