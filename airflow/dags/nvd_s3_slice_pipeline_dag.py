"""
NVD incremental via S3 slices (parallel): same date window and ``slice_days`` chunking as
``nvd_incremental_dag``. For each date slice, **three mapped Airflow tasks** run in sequence —
**fetch** (NVD → S3 raw), **transform** (raw → S3 curated), **load** (curated → Snowflake) — so
the graph shows which stage failed. Stages still share the same NVD API chunk size per slice
(``slice_days``) and deterministic S3 keys.

Checkpoint source: ``ingestion_checkpoints`` row **``nvd_s3_slice_pipeline_through``** (separate
from ``nvd_api_last_modified_through`` used by ``nvd_incremental_dag``). Watermark advances to
each slice **end** date only after **load** succeeds.

Optional ``dag_run.conf``: ``force_start``, ``force_end`` (ISO dates), ``slice_days`` (default 7),
``prefix`` (default ``nvd``). Raw: ``{prefix}/raw/slices/YYYY-MM-DD_YYYY-MM-DD.jsonl``;
curated: ``{prefix}/curated/slices/YYYY-MM-DD_YYYY-MM-DD.ndjson``.

Overlapping date ranges with ``nvd_incremental_dag`` still **MERGE** safely in Snowflake but
duplicate NVD API work.

Requires ``S3_BUCKET``, AWS credentials, Snowflake, ``NVD_API_KEY`` (recommended), and
``07_ingestion_monitoring.sql`` applied.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any

import pendulum
from airflow.decorators import dag, task

_DAG_DIR = Path(__file__).resolve().parent
if str(_DAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DAG_DIR))

from lib.nvd_months import ensure_repo_imports  # noqa: E402

default_args = {
    "owner": "cti",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=15),
}


@dag(
    dag_id="nvd_s3_slice_pipeline_dag",
    default_args=default_args,
    description="NVD API delta → S3 slice raw → S3 slice curated → Snowflake (mapped fetch/transform/load per slice).",
    schedule=None,
    start_date=pendulum.datetime(2020, 1, 1, tz="UTC"),
    catchup=False,
    tags=["nvd", "snowflake", "s3", "incremental"],
    doc_md=__doc__,
)
def build_nvd_s3_slice_pipeline_dag():
    @task(task_id="build_slices")
    def build_slices(**context) -> list[dict[str, str]]:
        ensure_repo_imports()
        from app.config import get_settings
        from ingestion.monitoring import (
            resolve_nvd_s3_slice_window,
            slice_date_range,
        )

        dr = context.get("dag_run")
        conf = (dr.conf if dr else None) or {}
        ti = context["ti"]

        b = (get_settings().s3_bucket or "").strip()
        if not b:
            raise ValueError("S3_BUCKET not set in environment.")

        prefix = (conf.get("prefix") or "nvd").strip().strip("/")
        slice_days = int(conf.get("slice_days") or 7)

        start_d, end_d = resolve_nvd_s3_slice_window(conf)
        slices = slice_date_range(start_d, end_d, max_days=slice_days)
        ti.log.info(
            "NVD S3 slice window %s .. %s (%s slices), prefix=%s",
            start_d,
            end_d,
            len(slices),
            prefix,
        )

        return [
            {
                "bucket": b,
                "prefix": prefix,
                "start": s.isoformat(),
                "end": e.isoformat(),
            }
            for s, e in slices
        ]

    @task(task_id="fetch_slice")
    def fetch_slice(slice_row: dict[str, str], **context) -> dict[str, Any]:
        ensure_repo_imports()
        from ingestion.monitoring import complete_pipeline_run, start_pipeline_run
        from ingestion.nvd.pipeline import fetch_delta_to_raw_file
        from ingestion.nvd.s3_slice_paths import slice_curated_s3_uri, slice_raw_s3_uri

        s = date.fromisoformat(slice_row["start"])
        e = date.fromisoformat(slice_row["end"])
        bucket = slice_row["bucket"]
        prefix = slice_row["prefix"]
        raw_uri = slice_raw_s3_uri(bucket, prefix, s, e)
        curated_uri = slice_curated_s3_uri(bucket, prefix, s, e)

        dr = context.get("dag_run")
        ti = context["ti"]
        dag = context["dag"]

        run_id = start_pipeline_run(
            dag_id=dag.dag_id,
            source="nvd",
            logical_source="nvd_s3_slice_fetch",
            airflow_dag_run_id=getattr(dr, "run_id", None),
            airflow_task_id=ti.task_id,
            watermark_from=datetime.combine(s, time.min),
            watermark_to=datetime.combine(e, time(23, 59, 59)),
        )

        stats: dict[str, Any] = {"slice_start": str(s), "slice_end": str(e), "raw_uri": raw_uri}
        try:
            fetch_stats = fetch_delta_to_raw_file(s, e, raw_uri)
            ti.log.info("NVD S3 fetch %s..%s: %s", s, e, fetch_stats)
            return {
                **slice_row,
                "run_id": run_id,
                "raw_uri": raw_uri,
                "curated_uri": curated_uri,
                "slice_start": str(s),
                "slice_end": str(e),
                "fetch_stats": fetch_stats,
            }
        except Exception as exc:
            complete_pipeline_run(
                run_id,
                status="failed",
                error_message=str(exc)[:8000],
                stats=stats,
            )
            raise

    @task(task_id="transform_slice")
    def transform_slice(payload: dict[str, Any], **context) -> dict[str, Any]:
        ensure_repo_imports()
        from ingestion.monitoring import complete_pipeline_run
        from ingestion.nvd.pipeline import transform_raw_file_to_curated

        run_id = payload["run_id"]
        raw_uri = payload["raw_uri"]
        curated_uri = payload["curated_uri"]
        s = date.fromisoformat(str(payload["start"])[:10])
        e = date.fromisoformat(str(payload["end"])[:10])

        stats: dict[str, Any] = {
            "slice_start": payload.get("slice_start"),
            "slice_end": payload.get("slice_end"),
            "raw_uri": raw_uri,
            "fetch": payload.get("fetch_stats"),
        }
        try:
            xform_stats = transform_raw_file_to_curated(raw_uri, curated_uri)
            context["ti"].log.info("NVD S3 transform %s..%s: %s", s, e, xform_stats)
            return {**payload, "transform_stats": xform_stats}
        except Exception as exc:
            stats["transform"] = None
            complete_pipeline_run(
                run_id,
                status="failed",
                error_message=str(exc)[:8000],
                stats=stats,
            )
            raise

    @task(task_id="load_slice")
    def load_slice(payload: dict[str, Any], **context) -> dict[str, Any]:
        ensure_repo_imports()
        from ingestion.monitoring import (
            NVD_S3_SLICE_SOURCE,
            complete_pipeline_run,
            upsert_checkpoint,
        )
        from ingestion.nvd.pipeline import load_curated_file_to_snowflake

        run_id = payload["run_id"]
        curated_uri = payload["curated_uri"]
        fetch_stats = payload["fetch_stats"]
        xform_stats = payload["transform_stats"]
        s = date.fromisoformat(str(payload["start"])[:10])
        e = date.fromisoformat(str(payload["end"])[:10])
        raw_uri = payload["raw_uri"]

        stats: dict[str, Any] = {
            "slice_start": str(s),
            "slice_end": str(e),
            "raw_uri": raw_uri,
            "fetch": fetch_stats,
            "transform": xform_stats,
        }
        try:
            load_stats = load_curated_file_to_snowflake(curated_uri, batch_size=2000)
            stats["load"] = load_stats

            upsert_checkpoint(
                NVD_S3_SLICE_SOURCE,
                watermark_date=e,
                last_run_id=run_id,
                notes={
                    "slice_start": str(s),
                    "slice_end": str(e),
                    "fetched": fetch_stats.get("fetched"),
                    "raw_uri": raw_uri,
                    "curated_uri": curated_uri,
                },
            )

            complete_pipeline_run(
                run_id,
                status="success",
                stats=stats,
                records_fetched=int(fetch_stats.get("fetched", 0) or 0),
                records_new=int(load_stats.get("rows_upserted", 0) or 0),
            )
            context["ti"].log.info("NVD S3 load %s..%s ok: %s", s, e, stats)
            return stats
        except Exception as exc:
            complete_pipeline_run(
                run_id,
                status="failed",
                error_message=str(exc)[:8000],
                stats=stats,
            )
            raise

    rows = build_slices()
    fetched = fetch_slice.expand(slice_row=rows)
    xformed = transform_slice.expand(payload=fetched)
    loaded = load_slice.expand(payload=xformed)
    rows >> fetched >> xformed >> loaded


nvd_s3_slice_pipeline_dag = build_nvd_s3_slice_pipeline_dag()
