"""
NVD batch transform (DAG 2): ``schedule=None``, triggered by ``nvd_fetch_dag``.

Lists ``s3://$S3_BUCKET/nvd/raw/YYYY-MM.jsonl`` in the batch window, transforms each to
``.../curated/YYYY-MM.ndjson`` on S3 (no NVD API, no Snowflake).

On success, triggers ``nvd_load_dag`` with ``wait_for_completion=True``.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pendulum
from airflow.decorators import dag, task
from airflow.operators.trigger_dagrun import TriggerDagRunOperator

_DAG_DIR = Path(__file__).resolve().parent
if str(_DAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DAG_DIR))

from lib.nvd_months import (  # noqa: E402
    curated_s3_uri,
    ensure_repo_imports,
    in_nvd_batch_window,
    ym_tuple_from_key,
)

default_args = {
    "owner": "cti",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=10),
}


@dag(
    dag_id="nvd_transform_dag",
    default_args=default_args,
    description="S3 raw NDJSON → S3 curated NDJSON (discover keys); then trigger load DAG.",
    schedule=None,
    start_date=pendulum.datetime(2020, 1, 1, tz="UTC"),
    catchup=False,
    tags=["nvd", "s3", "transform"],
    doc_md=__doc__,
)
def build_nvd_transform_dag():
    @task(task_id="list_raw_curated_pairs")
    def list_raw_curated_pairs(**context) -> list[list[str]]:
        ensure_repo_imports()
        from app.config import get_settings
        from ingestion.nvd.s3_io import list_s3_keys

        conf = context["dag_run"].conf or {}
        prefix = (conf.get("prefix") or "nvd").strip().strip("/")
        b = (get_settings().s3_bucket or "").strip()
        if not b:
            raise ValueError("S3_BUCKET not set in environment.")
        keys = list_s3_keys(b, prefix)
        pairs: list[list[str]] = []
        for k in keys:
            if "/raw/" not in k or not k.endswith(".jsonl"):
                continue
            ym = ym_tuple_from_key(k)
            if ym is None or not in_nvd_batch_window(ym):
                continue
            y, m = ym
            raw_uri = f"s3://{b}/{k}"
            cur = curated_s3_uri(b, prefix, y, m)
            pairs.append([raw_uri, cur])
        pairs.sort(key=lambda p: p[0])
        if not pairs:
            raise ValueError("No raw .jsonl keys found in S3 for the NVD batch window.")
        context["ti"].log.info("Transform pair count: %s", len(pairs))
        return pairs

    @task(task_id="transform_one_month")
    def transform_one_month(pair: list[str], **context) -> dict:
        ensure_repo_imports()
        from ingestion.nvd.pipeline import transform_raw_file_to_curated

        raw_uri, curated_uri = pair[0], pair[1]
        stats = transform_raw_file_to_curated(raw_uri, curated_uri)
        context["ti"].log.info("transform %s -> %s: %s", raw_uri, curated_uri, stats)
        return stats

    pairs = list_raw_curated_pairs()
    mapped = transform_one_month.expand(pair=pairs)

    trigger_load = TriggerDagRunOperator(
        task_id="trigger_load",
        trigger_dag_id="nvd_load_dag",
        wait_for_completion=True,
        conf={"prefix": "nvd"},
    )

    pairs >> mapped >> trigger_load


nvd_transform_dag = build_nvd_transform_dag()
