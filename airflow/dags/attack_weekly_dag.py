"""
MITRE ATT&CK weekly full refresh (DAG): fetch STIX bundle, transform, upsert to Snowflake.

Manual trigger or weekly schedule. Requires Snowflake creds in environment.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

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
    "retries": 2,
    "retry_delay": timedelta(minutes=10),
}


def run_attack_reload(**context) -> dict:
    ensure_repo_imports()
    from ingestion.attack.pipeline import run_attack_full_reload
    from ingestion.monitoring.snowflake_runs import complete_pipeline_run, start_pipeline_run

    dr = context.get("dag_run")
    rid = start_pipeline_run(
        dag_id="attack_weekly_dag",
        source="attack",
        logical_source="attack_full_reload",
        airflow_dag_run_id=getattr(dr, "run_id", None),
        airflow_task_id=context["ti"].task_id,
    )
    try:
        stats = run_attack_full_reload()
        complete_pipeline_run(rid, status="success", stats=stats)
        context["ti"].log.info("ATT&CK reload stats: %s", stats)
        return stats
    except Exception as exc:
        complete_pipeline_run(rid, status="failed", error_message=str(exc)[:8000])
        raise


with DAG(
    dag_id="attack_weekly_dag",
    default_args=default_args,
    description="MITRE ATT&CK STIX full refresh into Snowflake weekly.",
    schedule="0 4 * * 0",
    start_date=pendulum.datetime(2026, 1, 1, tz="UTC"),
    catchup=False,
    tags=["attack", "mitre", "snowflake", "ingest"],
    doc_md=__doc__,
) as dag:
    ingest_attack = PythonOperator(
        task_id="ingest_attack_full_reload",
        python_callable=run_attack_reload,
    )
