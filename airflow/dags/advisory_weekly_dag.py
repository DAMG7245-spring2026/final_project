"""
CISA Advisory weekly pipeline (DAG): every Sunday 06:00 UTC, scrape new CISA
Analysis Reports + Cybersecurity Advisories, classify document_type, re-chunk
every advisory with chunker_v2, then compute Snowflake Cortex embeddings for
both chunks and full reports.

Dedup is by ``advisory_id`` (the final segment of the CISA URL slug, e.g.
``aa25-343a``), which is the PK on ``advisories``. The scraper skips rows
already present, and the chunk loader DELETE+INSERTs per-advisory, so reruns
are idempotent.

Runs after ``nvd_weekly_delta_dag`` (05:00) and ``kev_weekly_dag`` (05:30) so
downstream joins can see the latest CVE rows.

Task chain:
  scrape_advisories                  (emits {new_count, new_ids} via XCom)
    └── classify_document_types      (needed before chunk — chunker_v2 branches on it)
          └── chunk_advisories        (pulls new_ids XCom — only re-chunks new rows)
                ├── embed_chunks      (chunk-level, 1024-dim Cortex; embeds NULLs)
                └── embed_reports     (report-level, LISTAGG+Cortex; embeds NULLs)
                      ├── rebuild_bm25     (pickle cache in data/bm25_index.pkl)
                      └── extract_triplets (Phase 1: kNN ICL + GPT-4o → extracted_triplets)
                            └── align_entities  (Phase 2: dedup alias across whole table)
                                  └── load_neo4j    (Phase 4: Snowflake → Neo4j nodes/edges)
                                        └── infer_relations (Phase 3: close disconnected subgraphs)

Incremental design: the scraper only inserts advisories whose ``advisory_id``
is new, so we only need to chunk + embed those same rows. Phase 1/4/3 also
consume ``new_ids`` and short-circuit to zero work when empty.
``align_entities`` always sweeps the whole ``extracted_triplets`` table when
triggered (new entities may alias existing ones) but is skipped entirely when
``new_ids`` is empty. If the scraper finds nothing new, every downstream
task no-ops quickly while ``rebuild_bm25`` still refreshes its pickle.

Requires Snowflake + AWS creds in env.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pendulum
from airflow import DAG
from airflow.operators.python import PythonOperator

# Make the repo root importable so ``ingestion.*`` resolves at DAG parse time.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


default_args = {
    "owner": "cti",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=10),
}


def _run_scrape(**context) -> dict:
    from ingestion.advisory.scraper import scrape_advisories

    new_items = scrape_advisories()
    stats = {
        "new_count": len(new_items),
        "new_ids": [m.advisory_id for m in new_items],
    }
    context["ti"].log.info("advisory_scrape: %s", stats)
    return stats


def _run_classify(**context) -> dict:
    from ingestion.advisory.classifier import run_backfill_document_type

    stats = run_backfill_document_type(write=True)
    context["ti"].log.info("advisory_classify: %s", stats)
    return stats


def _run_chunk(**context) -> dict:
    from ingestion.advisory.chunk_loader import run_chunk_all

    ti = context["ti"]
    scrape_stats = ti.xcom_pull(task_ids="scrape_advisories") or {}
    new_ids = scrape_stats.get("new_ids", [])
    ti.log.info("advisory_chunk: received %d new advisory_id(s) from scrape", len(new_ids))

    stats = run_chunk_all(advisory_ids=new_ids, commit=True)
    ti.log.info("advisory_chunk: %s", stats)
    return stats


def _run_embed_chunks(**context) -> dict:
    from ingestion.advisory.embedder import run_embed_chunks

    # force=False → only rows with chunk_embedding IS NULL (the newly-inserted
    # chunks from chunk_advisories). Existing chunks keep their embeddings.
    stats = run_embed_chunks(write=True)
    context["ti"].log.info("advisory_embed_chunks: %s", stats)
    return stats


def _run_embed_reports(**context) -> dict:
    from ingestion.advisory.embedder import run_embed_reports

    # force=False → only rows with report_embedding IS NULL (new advisories).
    # Existing reports keep their embeddings — chunker is deterministic for
    # the same (html, document_type), so chunk_text LISTAGG doesn't change
    # on reruns and existing report_embedding stays valid.
    stats = run_embed_reports(write=True)
    context["ti"].log.info("advisory_embed_reports: %s", stats)
    return stats


def _run_rebuild_bm25(**context) -> dict:
    from app.services.bm25_index import rebuild_bm25_index

    stats = rebuild_bm25_index()
    context["ti"].log.info("advisory_bm25_rebuild: %s", stats)
    return stats


def _new_ids_from_xcom(ti) -> list[str]:
    scrape_stats = ti.xcom_pull(task_ids="scrape_advisories") or {}
    return list(scrape_stats.get("new_ids", []))


def _run_extract_triplets(**context) -> dict:
    from ingestion.advisory.triplets import run_extract_triplets

    ti = context["ti"]
    new_ids = _new_ids_from_xcom(ti)
    ti.log.info("advisory_extract_triplets: received %d new advisory_id(s)", len(new_ids))
    stats = run_extract_triplets(advisory_ids=new_ids, commit=True)
    ti.log.info("advisory_extract_triplets: %s", stats)
    return stats


def _run_align_entities(**context) -> dict:
    from ingestion.advisory.triplets import run_align_entities

    ti = context["ti"]
    new_ids = _new_ids_from_xcom(ti)
    ti.log.info("advisory_align_entities: received %d new advisory_id(s)", len(new_ids))
    stats = run_align_entities(advisory_ids=new_ids, commit=True)
    ti.log.info("advisory_align_entities: %s", stats)
    return stats


def _run_load_neo4j(**context) -> dict:
    from ingestion.advisory.triplets import run_load_neo4j

    ti = context["ti"]
    new_ids = _new_ids_from_xcom(ti)
    ti.log.info("advisory_load_neo4j: received %d new advisory_id(s)", len(new_ids))
    stats = run_load_neo4j(advisory_ids=new_ids, commit=True)
    ti.log.info("advisory_load_neo4j: %s", stats)
    return stats


def _run_infer_relations(**context) -> dict:
    from ingestion.advisory.triplets import run_infer_relations

    ti = context["ti"]
    new_ids = _new_ids_from_xcom(ti)
    ti.log.info("advisory_infer_relations: received %d new advisory_id(s)", len(new_ids))
    stats = run_infer_relations(advisory_ids=new_ids, commit=True)
    ti.log.info("advisory_infer_relations: %s", stats)
    return stats


with DAG(
    dag_id="advisory_weekly_dag",
    default_args=default_args,
    description="CISA advisory scrape → classify → chunk → Cortex embed (chunks + reports).",
    schedule="0 6 * * 0",
    start_date=pendulum.datetime(2026, 4, 1, tz="UTC"),
    catchup=False,
    tags=["advisory", "cisa", "weekly", "snowflake", "ingest"],
    doc_md=__doc__,
) as dag:
    scrape = PythonOperator(
        task_id="scrape_advisories",
        python_callable=_run_scrape,
    )
    classify = PythonOperator(
        task_id="classify_document_types",
        python_callable=_run_classify,
    )
    chunk = PythonOperator(
        task_id="chunk_advisories",
        python_callable=_run_chunk,
    )
    embed_chunks = PythonOperator(
        task_id="embed_chunks",
        python_callable=_run_embed_chunks,
    )
    embed_reports = PythonOperator(
        task_id="embed_reports",
        python_callable=_run_embed_reports,
    )
    rebuild_bm25 = PythonOperator(
        task_id="rebuild_bm25",
        python_callable=_run_rebuild_bm25,
    )
    extract_triplets = PythonOperator(
        task_id="extract_triplets",
        python_callable=_run_extract_triplets,
    )
    align_entities = PythonOperator(
        task_id="align_entities",
        python_callable=_run_align_entities,
    )
    load_neo4j = PythonOperator(
        task_id="load_neo4j",
        python_callable=_run_load_neo4j,
    )
    infer_relations = PythonOperator(
        task_id="infer_relations",
        python_callable=_run_infer_relations,
    )

    scrape >> classify >> chunk >> [embed_chunks, embed_reports] >> rebuild_bm25
    embed_reports >> extract_triplets >> align_entities >> load_neo4j >> infer_relations
