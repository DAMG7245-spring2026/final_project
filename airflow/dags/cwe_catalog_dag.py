"""
Infrequent CWE catalog bulk load from a JSON file path (Airflow Variable or dag_run.conf).

Variable ``CWE_CATALOG_PATH`` or conf ``catalog_path`` must point to a MITRE-style catalog JSON.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pendulum
from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import PythonOperator

_DAG_DIR = Path(__file__).resolve().parent
if str(_DAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DAG_DIR))

from lib.nvd_months import ensure_repo_imports  # noqa: E402

default_args = {"owner": "cti", "depends_on_past": False, "retries": 0}


def run_cwe_catalog_load(**context) -> dict:
    ensure_repo_imports()
    from ingestion.cwe.loader import load_cwe_records
    from ingestion.monitoring.snowflake_runs import complete_pipeline_run, start_pipeline_run

    dr = context.get("dag_run")
    conf = (dr.conf if dr else None) or {}
    path = (conf.get("catalog_path") or "").strip() or Variable.get("CWE_CATALOG_PATH", default_var="").strip()
    if not path:
        raise ValueError("Set dag_run.conf catalog_path or Airflow Variable CWE_CATALOG_PATH")

    rid = start_pipeline_run(
        dag_id="cwe_catalog_dag",
        source="cwe",
        logical_source="cwe_catalog_load",
        airflow_dag_run_id=getattr(dr, "run_id", None),
        airflow_task_id=context["ti"].task_id,
    )
    try:
        n = load_cwe_records(path)
        stats = {"catalog_path": path, "rows_processed": n}
        complete_pipeline_run(rid, status="success", stats=stats, records_new=n)
        return stats
    except Exception as exc:
        complete_pipeline_run(rid, status="failed", error_message=str(exc)[:8000])
        raise


with DAG(
    dag_id="cwe_catalog_dag",
    default_args=default_args,
    description="Bulk load CWE catalog JSON into Snowflake (manual).",
    schedule=None,
    start_date=pendulum.datetime(2024, 1, 1, tz="UTC"),
    catchup=False,
    tags=["cwe", "snowflake"],
    doc_md=__doc__,
) as dag:
    PythonOperator(task_id="load_cwe_catalog", python_callable=run_cwe_catalog_load)
