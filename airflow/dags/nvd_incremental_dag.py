"""
NVD incremental catch-up: resolve [start, end] from Snowflake checkpoints / MAX(last_modified),
then run sync_delta for each sub-range (default 7-day slices) sequentially.

Manual or scheduled trigger. Optional dag_run.conf:
  force_start, force_end (ISO dates), slice_days (int, default 7).

Requires Snowflake 07_ingestion_monitoring.sql applied, NVD_API_KEY, Snowflake creds.
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path
from time import perf_counter

import pendulum
from airflow import DAG
from airflow.operators.python import PythonOperator

_DAG_DIR = Path(__file__).resolve().parent
if str(_DAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DAG_DIR))

from lib.nvd_months import ensure_repo_imports  # noqa: E402

default_args = {
    "owner": "cti",
    "depends_on_past": False,
    "retries": 1,
}


def run_nvd_incremental_catchup(**context) -> dict:
    ensure_repo_imports()
    from ingestion.monitoring import (
        NVD_INCREMENTAL_SOURCE,
        complete_pipeline_run,
        resolve_nvd_date_window,
        slice_date_range,
        start_pipeline_run,
        upsert_checkpoint,
    )
    from ingestion.nvd.pipeline import sync_delta

    dr = context.get("dag_run")
    conf = (dr.conf if dr else None) or {}
    ti = context["ti"]

    start_d, end_d = resolve_nvd_date_window(conf)
    slice_days = int(conf.get("slice_days") or 7)
    slices = slice_date_range(start_d, end_d, max_days=slice_days)
    ti.log.info("NVD incremental window %s .. %s (%s slices)", start_d, end_d, len(slices))

    run_id = start_pipeline_run(
        dag_id=context["dag"].dag_id,
        source="nvd",
        logical_source="nvd_incremental",
        airflow_dag_run_id=getattr(dr, "run_id", None),
        airflow_task_id=ti.task_id,
        watermark_from=None,
        watermark_to=None,
    )

    agg = {"slices": 0, "fetched": 0, "upserted": 0, "window_start": str(start_d), "window_end": str(end_d)}
    t0 = perf_counter()
    try:
        for s, e in slices:
            stats = sync_delta(s, e)
            agg["slices"] += 1
            agg["fetched"] += int(stats.get("fetched", 0))
            agg["upserted"] += int(stats.get("upserted", 0))
            upsert_checkpoint(
                NVD_INCREMENTAL_SOURCE,
                watermark_date=e,
                last_run_id=run_id,
                notes={"slice_start": str(s), "slice_end": str(e), "fetched": stats.get("fetched")},
            )
            ti.log.info("NVD slice %s..%s ok: %s", s, e, stats)
        complete_pipeline_run(
            run_id,
            status="success",
            stats=agg,
            records_fetched=agg["fetched"],
            records_new=agg["upserted"],
        )
        agg["elapsed_sec"] = perf_counter() - t0
        return agg
    except Exception as exc:
        complete_pipeline_run(run_id, status="failed", error_message=str(exc)[:8000], stats=agg)
        raise


with DAG(
    dag_id="nvd_incremental_dag",
    default_args=default_args,
    description="NVD API delta → Snowflake using dynamic window + ingestion_checkpoints.",
    schedule=None,
    start_date=pendulum.datetime(2020, 1, 1, tz="UTC"),
    catchup=False,
    tags=["nvd", "snowflake", "incremental"],
    doc_md=__doc__,
) as dag:
    PythonOperator(
        task_id="nvd_incremental_catchup",
        python_callable=run_nvd_incremental_catchup,
    )
