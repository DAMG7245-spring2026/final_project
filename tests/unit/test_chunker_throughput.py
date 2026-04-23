"""Throughput test: 2 real CISA advisories per document type chunked within 2 minutes.

Document types covered: MAR, ANALYSIS_REPORT, JOINT_CSA, STOPRANSOMWARE, CSA, IR_LESSONS
Total: 6 types × 2 advisories = 12 advisories

Pipeline under test:
  Snowflake (advisory_id, document_type, s3_raw_path)
  → S3 download HTML
  → chunk_advisory() [chunker_v2]

Pass criteria:
  - Every document type is represented by exactly 2 advisories
  - All advisories produce >= 1 chunk
  - Total wall-clock time (including S3 downloads) <= 120 seconds
  - No chunk exceeds HARD_MAX_TOKENS
"""
import time

import boto3
import pytest
import snowflake.connector
from dotenv import load_dotenv

load_dotenv()

from app.config import get_settings
from ingestion.advisory.chunker_v2 import HARD_MAX_TOKENS, TYPE_STRATEGY, chunk_advisory

DEADLINE_SECONDS = 120
PER_TYPE = 2
DOC_TYPES = list(TYPE_STRATEGY.keys())  # MAR, ANALYSIS_REPORT, JOINT_CSA, STOPRANSOMWARE, CSA, IR_LESSONS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sf_conn():
    s = get_settings()
    conn = snowflake.connector.connect(
        account=s.snowflake_account,
        user=s.snowflake_user,
        password=s.snowflake_password,
        database=s.snowflake_database,
        schema=s.snowflake_schema,
        warehouse=s.snowflake_warehouse,
    )
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def s3_client():
    s = get_settings()
    return boto3.client(
        "s3",
        aws_access_key_id=s.aws_access_key_id,
        aws_secret_access_key=s.aws_secret_access_key,
        region_name=s.aws_region,
    )


@pytest.fixture(scope="module")
def advisories(sf_conn):
    """Fetch 2 advisories per document_type (6 types → 12 rows total)."""
    cur = sf_conn.cursor()
    rows: list[tuple[str, str, str]] = []

    for doc_type in DOC_TYPES:
        cur.execute("""
            SELECT advisory_id, document_type, s3_raw_path
            FROM advisories
            WHERE document_type = %s
              AND s3_raw_path IS NOT NULL
            ORDER BY published_date DESC
            LIMIT %s
        """, (doc_type, PER_TYPE))
        fetched = cur.fetchall()
        assert len(fetched) == PER_TYPE, (
            f"document_type='{doc_type}': expected {PER_TYPE} advisories, got {len(fetched)}"
        )
        rows.extend(fetched)

    cur.close()
    return rows  # list of (advisory_id, document_type, s3_raw_path)


@pytest.fixture(scope="module")
def throughput_results(advisories, s3_client):
    """
    Run the full S3-download → chunk_advisory pipeline for all 12 advisories.
    Returns (elapsed_seconds, list of (advisory_id, document_type, chunk_count)).
    """
    s = get_settings()
    results: list[tuple[str, str, int, float, int]] = []
    t0 = time.perf_counter()

    for advisory_id, document_type, s3_raw_path in advisories:
        t1 = time.perf_counter()
        resp = s3_client.get_object(Bucket=s.s3_bucket, Key=s3_raw_path)
        html = resp["Body"].read().decode("utf-8", errors="replace")
        html_kb = len(html.encode("utf-8")) // 1024
        chunks = chunk_advisory(advisory_id, document_type, html)
        results.append((advisory_id, document_type, len(chunks), time.perf_counter() - t1, html_kb))

    elapsed = time.perf_counter() - t0
    return elapsed, results


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestChunkerThroughput:

    def test_completes_within_deadline(self, throughput_results):
        elapsed, _ = throughput_results
        assert elapsed <= DEADLINE_SECONDS, (
            f"12 advisories took {elapsed:.2f}s — exceeded {DEADLINE_SECONDS}s deadline"
        )

    def test_all_advisories_produce_chunks(self, throughput_results):
        _, results = throughput_results
        for advisory_id, _, count, _, _ in results:
            assert count >= 1, f"{advisory_id} produced 0 chunks"

    def test_all_doc_types_covered(self, throughput_results):
        _, results = throughput_results
        found_types = {doc_type for _, doc_type, _, _, _ in results}
        missing = set(DOC_TYPES) - found_types
        assert not missing, f"Missing document types in results: {missing}"

    def test_no_chunk_exceeds_hard_token_limit(self, advisories, s3_client):
        s = get_settings()
        for advisory_id, document_type, s3_raw_path in advisories:
            resp = s3_client.get_object(Bucket=s.s3_bucket, Key=s3_raw_path)
            html = resp["Body"].read().decode("utf-8", errors="replace")
            chunks = chunk_advisory(advisory_id, document_type, html)
            for chunk in chunks:
                assert chunk.token_count <= HARD_MAX_TOKENS, (
                    f"{chunk.chunk_id}: {chunk.token_count} tokens > hard limit {HARD_MAX_TOKENS}"
                )

    def test_throughput_report(self, throughput_results, capsys):
        elapsed, results = throughput_results
        total_chunks = sum(c for _, _, c, _, _ in results)
        total_kb = sum(kb for _, _, _, _, kb in results)
        rate = len(results) / elapsed if elapsed > 0 else float("inf")
        with capsys.disabled():
            print(f"\n{'='*75}")
            print(f"  Unstructured Data Throughput Report  ({PER_TYPE} per type)")
            print(f"{'='*75}")
            print(f"  {'Advisory':<20} {'Type':<18} {'Chunks':>6}  {'Time':>7}  {'HTML':>7}")
            print(f"  {'─'*20} {'─'*18} {'─'*6}  {'─'*7}  {'─'*7}")
            for doc_type in DOC_TYPES:
                for advisory_id, dt, count, t, kb in results:
                    if dt == doc_type:
                        print(f"  {advisory_id:<20} {doc_type:<18} {count:>6}  {t:>6.2f}s  {kb:>5}KB")
            print(f"{'─'*75}")
            print(f"  Advisories  : {len(results)} ({len(DOC_TYPES)} types × {PER_TYPE})")
            print(f"  Total chunks: {total_chunks}")
            print(f"  Total HTML  : {total_kb} KB downloaded from S3")
            print(f"  Elapsed     : {elapsed:.2f}s  (wall-clock incl. S3 downloads)")
            print(f"  Rate        : {rate:.2f} docs/s")
            print(f"  Deadline    : {DEADLINE_SECONDS}s  "
                  f"{'PASS ✓' if elapsed <= DEADLINE_SECONDS else 'FAIL ✗'}")
            print(f"{'='*75}\n")
