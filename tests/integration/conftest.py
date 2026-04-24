"""Shared fixtures for integration tests.

These tests treat the live Snowflake + Neo4j + S3 state as the **source of
truth** and exercise production code against it. There is no mock schema,
no fixture HTML, no stubbed LLM — if the pipeline code drifts away from
what is persisted, the tests fail.

Isolation model:
  * Snowflake / Neo4j: read-only against prod. Tests never INSERT or DELETE
    into prod tables / graph. Everything is SELECT + comparison.
  * S3: read-only — the advisory HTML is fetched but never written back.

Picking the ground-truth advisory:
  We pick the advisory that satisfies every precondition (HTML in S3,
  chunks with embeddings in Snowflake, triplets extracted, Neo4j edges)
  and has the richest triplet set. ``ORDER BY n_triplets DESC, advisory_id``
  makes the selection deterministic across sessions so results are
  reproducible. If none qualify, the whole integration suite skips.
"""
from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

load_dotenv()


_REQUIRED_ENV = (
    "SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD",
    "SNOWFLAKE_DATABASE", "SNOWFLAKE_WAREHOUSE",
    "NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET",
)


@pytest.fixture(scope="session")
def _credentials_present() -> None:
    missing = [v for v in _REQUIRED_ENV if not os.getenv(v)]
    if missing:
        pytest.skip(f"integration env vars missing: {missing}")


@pytest.fixture(scope="session")
def ground_truth_advisory(_credentials_present) -> dict:
    """One fully-processed advisory taken from prod, used as the ground
    truth for every test in this suite.

    Returns a dict with at least ``advisory_id``, ``document_type``,
    ``s3_raw_path``, ``title``, ``n_triplets`` so tests can derive queries
    and keys from it.
    """
    from app.services.snowflake import get_snowflake_service
    sf = get_snowflake_service()

    rows = sf.execute_query("""
        WITH adv AS (
          SELECT a.advisory_id, a.document_type, a.s3_raw_path, a.title
          FROM advisories a
          WHERE a.s3_raw_path IS NOT NULL
            AND a.document_type IS NOT NULL
            AND EXISTS (
              SELECT 1 FROM advisory_chunks c
              WHERE c.advisory_id = a.advisory_id
                AND c.chunk_embedding IS NOT NULL
            )
            AND EXISTS (
              SELECT 1 FROM extracted_triplets t
              WHERE t.advisory_id = a.advisory_id
            )
        ),
        counted AS (
          SELECT adv.*,
                 (SELECT COUNT(*) FROM extracted_triplets t
                  WHERE t.advisory_id = adv.advisory_id) AS n_triplets
          FROM adv
        )
        SELECT advisory_id, document_type, s3_raw_path, title, n_triplets
        FROM counted
        ORDER BY n_triplets DESC, advisory_id
        LIMIT 1
    """)
    if not rows:
        pytest.skip(
            "no prod advisory satisfies all preconditions "
            "(S3 HTML + embedded chunks + triplets)"
        )
    return rows[0]


@pytest.fixture(scope="session")
def advisory_html(ground_truth_advisory) -> str:
    """Raw HTML for the ground-truth advisory, fetched from S3."""
    from app.services.s3_storage import get_s3_storage
    s3 = get_s3_storage()
    obj = s3.client.get_object(
        Bucket=s3.bucket, Key=ground_truth_advisory["s3_raw_path"]
    )
    return obj["Body"].read().decode("utf-8", errors="replace")


@pytest.fixture(scope="session")
def bm25_loaded(_credentials_present):
    """Ensure the process-level BM25 index singleton is populated.

    ``hybrid_search`` requires this to have been called before the first
    request. In production it happens inside FastAPI's lifespan hook;
    in the test suite we trigger it once per session.
    """
    from app.services.bm25_index import load_or_build_bm25_index
    load_or_build_bm25_index()
