"""
Structured Snowflake → Neo4j: CVE/CWE/KEV batch sync, ATT&CK techniques, chunk co-occurrence edges.
Tasks are sequential (chunk links need CVE + Technique nodes).
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


def _cve_cwe_kev(**context) -> dict:
    ensure_repo_imports()
    from ingestion.graph_sync import run_cve_cwe_kev_sync
    from ingestion.monitoring.snowflake_runs import complete_pipeline_run, start_pipeline_run

    dr = context.get("dag_run")
    rid = start_pipeline_run(
        dag_id="neo4j_structured_sync_dag",
        source="neo4j",
        logical_source="neo4j_cve_cwe_kev",
        airflow_dag_run_id=getattr(dr, "run_id", None),
        airflow_task_id=context["ti"].task_id,
    )
    try:
        stats = run_cve_cwe_kev_sync()
        complete_pipeline_run(rid, status="success", stats=stats)
        return stats
    except Exception as exc:
        complete_pipeline_run(rid, status="failed", error_message=str(exc)[:8000])
        raise


def _attack_techniques(**context) -> dict:
    ensure_repo_imports()
    from ingestion.graph_sync import run_attack_techniques_sync
    from ingestion.monitoring.snowflake_runs import complete_pipeline_run, start_pipeline_run

    dr = context.get("dag_run")
    rid = start_pipeline_run(
        dag_id="neo4j_structured_sync_dag",
        source="neo4j",
        logical_source="neo4j_attack_techniques",
        airflow_dag_run_id=getattr(dr, "run_id", None),
        airflow_task_id=context["ti"].task_id,
    )
    try:
        stats = run_attack_techniques_sync()
        complete_pipeline_run(rid, status="success", stats=stats)
        return stats
    except Exception as exc:
        complete_pipeline_run(rid, status="failed", error_message=str(exc)[:8000])
        raise


def _chunk_technique_links(**context) -> dict:
    ensure_repo_imports()
    from ingestion.graph_sync import run_chunk_technique_link_sync
    from ingestion.monitoring.snowflake_runs import complete_pipeline_run, start_pipeline_run

    dr = context.get("dag_run")
    rid = start_pipeline_run(
        dag_id="neo4j_structured_sync_dag",
        source="neo4j",
        logical_source="neo4j_chunk_technique_links",
        airflow_dag_run_id=getattr(dr, "run_id", None),
        airflow_task_id=context["ti"].task_id,
    )
    try:
        stats = run_chunk_technique_link_sync()
        complete_pipeline_run(rid, status="success", stats=stats)
        return stats
    except Exception as exc:
        complete_pipeline_run(rid, status="failed", error_message=str(exc)[:8000])
        raise


with DAG(
    dag_id="neo4j_structured_sync_dag",
    default_args=default_args,
    description="Neo4j structured graph sync (CVE/CWE/KEV → techniques → chunk links).",
    schedule=None,
    start_date=pendulum.datetime(2024, 1, 1, tz="UTC"),
    catchup=False,
    tags=["neo4j", "graph", "structured"],
    doc_md=__doc__,
) as dag:
    a = PythonOperator(task_id="cve_cwe_kev_sync", python_callable=_cve_cwe_kev)
    b = PythonOperator(task_id="attack_techniques_sync", python_callable=_attack_techniques)
    c = PythonOperator(task_id="chunk_technique_links_sync", python_callable=_chunk_technique_links)
    a >> b >> c
