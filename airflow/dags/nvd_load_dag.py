"""
NVD batch load (DAG 3): ``schedule=None``, triggered by ``nvd_transform_dag``.

Lists curated ``*.ndjson`` under ``nvd/curated/`` in the batch window and MERGEs each
into Snowflake ``cve_records`` and ``cve_cwe_mappings`` (idempotent). Safe to re-run
without calling NVD.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pendulum
from airflow.decorators import dag, task

_DAG_DIR = Path(__file__).resolve().parent
if str(_DAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DAG_DIR))

from lib.nvd_months import (  # noqa: E402
    ensure_repo_imports,
    in_nvd_batch_window,
    ym_tuple_from_key,
)

default_args = {
    "owner": "cti",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=15),
}


@dag(
    dag_id="nvd_load_dag",
    default_args=default_args,
    description="S3 curated NDJSON → Snowflake cve_records + cve_cwe_mappings (MERGE), per month file.",
    schedule=None,
    start_date=pendulum.datetime(2020, 1, 1, tz="UTC"),
    catchup=False,
    tags=["nvd", "snowflake", "load"],
    doc_md=__doc__,
)
def build_nvd_load_dag():
    @task(task_id="list_curated_uris")
    def list_curated_uris(**context) -> list[str]:
        ensure_repo_imports()
        from app.config import get_settings
        from ingestion.nvd.s3_io import list_s3_keys

        conf = context["dag_run"].conf or {}
        prefix = (conf.get("prefix") or "nvd").strip().strip("/")
        b = (get_settings().s3_bucket or "").strip()
        if not b:
            raise ValueError("S3_BUCKET not set in environment.")
        keys = list_s3_keys(b, prefix)
        uris: list[str] = []
        for k in keys:
            if "/curated/" not in k or not k.endswith(".ndjson"):
                continue
            ym = ym_tuple_from_key(k)
            if ym is None or not in_nvd_batch_window(ym):
                continue
            uris.append(f"s3://{b}/{k}")
        uris.sort()
        if not uris:
            raise ValueError("No curated .ndjson keys found in S3 for the NVD batch window.")
        context["ti"].log.info("Load URI count: %s", len(uris))
        return uris

    @task(task_id="load_one_month")
    def load_one_month(curated_uri: str, **context) -> dict:
        ensure_repo_imports()
        from ingestion.nvd.pipeline import load_curated_file_to_snowflake

        stats = load_curated_file_to_snowflake(curated_uri, batch_size=2000)
        context["ti"].log.info("load %s: %s", curated_uri, stats)
        return stats

    uris = list_curated_uris()
    loads = load_one_month.expand(curated_uri=uris)
    uris >> loads


nvd_load_dag = build_nvd_load_dag()
