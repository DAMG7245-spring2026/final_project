"""
CISA KEV pipeline (three tasks): Snowflake enrichment, NVD drain for pending CVEs,
Neo4j CVE KEV property sync. See ingestion.kev / ingestion.graph_sync.kev_neo4j_sync.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pendulum
from airflow import DAG
from airflow.operators.python import PythonOperator

_DAG_DIR = Path(__file__).resolve().parent
if str(_DAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DAG_DIR))

from lib.nvd_months import ensure_repo_imports  # noqa: E402

default_args = {"owner": "cti", "depends_on_past": False, "retries": 1}


def _fetch_and_enrich(**context) -> dict:
    ensure_repo_imports()
    from ingestion.kev.enricher import run_fetch_and_enrich
    from ingestion.monitoring.snowflake_runs import complete_pipeline_run, start_pipeline_run

    dr = context.get("dag_run")
    rid = start_pipeline_run(
        dag_id="kev_sync_dag",
        source="kev",
        logical_source="kev_fetch_and_enrich",
        airflow_dag_run_id=getattr(dr, "run_id", None),
        airflow_task_id=context["ti"].task_id,
    )
    try:
        stats = run_fetch_and_enrich()
        complete_pipeline_run(rid, status="success", stats=stats)
        return stats
    except Exception as exc:
        complete_pipeline_run(rid, status="failed", error_message=str(exc)[:8000])
        raise


def _resolve_pending(**context) -> dict:
    ensure_repo_imports()
    from ingestion.kev.pending_resolver import run_resolve_kev_pending
    from ingestion.monitoring.snowflake_runs import complete_pipeline_run, start_pipeline_run

    dr = context.get("dag_run")
    rid = start_pipeline_run(
        dag_id="kev_sync_dag",
        source="kev",
        logical_source="kev_resolve_pending",
        airflow_dag_run_id=getattr(dr, "run_id", None),
        airflow_task_id=context["ti"].task_id,
    )
    try:
        stats = run_resolve_kev_pending()
        complete_pipeline_run(
            rid,
            status="success",
            stats=stats,
            records_new=stats.get("processed"),
        )
        return stats
    except Exception as exc:
        complete_pipeline_run(rid, status="failed", error_message=str(exc)[:8000])
        raise


def _sync_kev_neo4j(**context) -> dict:
    ensure_repo_imports()
    from ingestion.graph_sync.kev_neo4j_sync import run_sync_kev_neo4j
    from ingestion.monitoring.snowflake_runs import complete_pipeline_run, start_pipeline_run

    dr = context.get("dag_run")
    rid = start_pipeline_run(
        dag_id="kev_sync_dag",
        source="kev",
        logical_source="kev_sync_neo4j",
        airflow_dag_run_id=getattr(dr, "run_id", None),
        airflow_task_id=context["ti"].task_id,
    )
    try:
        stats = run_sync_kev_neo4j()
        complete_pipeline_run(
            rid,
            status="success",
            stats=stats,
            records_new=stats.get("cves_updated"),
        )
        return stats
    except Exception as exc:
        complete_pipeline_run(rid, status="failed", error_message=str(exc)[:8000])
        raise


with DAG(
    dag_id="kev_sync_dag",
    default_args=default_args,
    description="KEV: fetch_and_enrich → resolve_pending → sync_kev_neo4j",
    schedule=None,
    start_date=pendulum.datetime(2024, 1, 1, tz="UTC"),
    catchup=False,
    tags=["kev", "cisa", "snowflake", "neo4j"],
    doc_md=__doc__,
) as dag:
    t1 = PythonOperator(task_id="fetch_and_enrich", python_callable=_fetch_and_enrich)
    t2 = PythonOperator(task_id="resolve_pending", python_callable=_resolve_pending)
    t3 = PythonOperator(task_id="sync_kev_neo4j", python_callable=_sync_kev_neo4j)
    t1 >> t2 >> t3
