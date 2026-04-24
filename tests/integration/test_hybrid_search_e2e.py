"""Validate hybrid search against the live corpus.

Every test here calls ``app.services.hybrid_search.hybrid_search`` against
the real production BM25 index + Snowflake Cortex vectors. No seeding;
the corpus IS the test data.

Invariants covered:
  * Domain-relevant natural-language query returns the right advisory
    in the top-N (BM25 + vector + RRF fusion actually working).
  * ``document_types`` filter restricts results to exactly that doctype.
  * ``cve_ids`` filter only returns chunks that mention the target CVE.
  * Every result carries RRF annotations (rrf_score + at least one of
    bm25_rank / vec_rank).
"""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.integration


def _decode_array(col) -> list[str]:
    if col is None:
        return []
    if isinstance(col, str):
        return json.loads(col)
    return list(col)


def test_query_derived_from_title_finds_advisory_in_top_20(
    ground_truth_advisory, bm25_loaded,
):
    """Use the advisory's own title as a query — its chunks MUST appear in
    the top-20. If they don't, either BM25 isn't reading the right table,
    the vector branch is misconfigured, or RRF fusion is throwing hits
    out."""
    from app.services.hybrid_search import hybrid_search

    title = (ground_truth_advisory["title"] or "").strip()
    assert title, "ground-truth advisory has no title — cannot derive query"
    query = title[:160]

    results = hybrid_search(query=query, top_k=20, top_n=80)
    assert results, f"hybrid_search returned 0 hits for query {query!r}"

    advisory_ids = {r["advisory_id"] for r in results}
    assert ground_truth_advisory["advisory_id"] in advisory_ids, (
        f"Expected {ground_truth_advisory['advisory_id']} in top-20 for its "
        f"own title query, got {sorted(advisory_ids)}"
    )


def test_document_types_filter_restricts_to_that_doctype(
    ground_truth_advisory, bm25_loaded,
):
    """Results must only come from advisories with the filtered doctype."""
    from app.services.snowflake import get_snowflake_service
    from app.services.hybrid_search import hybrid_search

    sf = get_snowflake_service()
    dtype = ground_truth_advisory["document_type"]

    results = hybrid_search(
        query="threat actor activity",
        top_k=10,
        top_n=80,
        document_types=[dtype],
    )
    assert results, f"no hybrid_search hits under document_types=[{dtype}]"

    advisory_ids = sorted({r["advisory_id"] for r in results})
    placeholders = ",".join(["%s"] * len(advisory_ids))
    meta = sf.execute_query(
        f"SELECT advisory_id, document_type FROM advisories "
        f"WHERE advisory_id IN ({placeholders})",
        tuple(advisory_ids),
    )
    wrong = [m for m in meta if m["document_type"] != dtype]
    assert not wrong, (
        f"document_types=[{dtype}] filter let {len(wrong)} wrong-doctype "
        f"advisories through: {wrong}"
    )


def test_cve_ids_filter_only_returns_chunks_that_contain_cve(bm25_loaded):
    """Every returned chunk's cve_ids array must contain the requested CVE."""
    from app.services.snowflake import get_snowflake_service
    from app.services.hybrid_search import hybrid_search

    sf = get_snowflake_service()
    # Pick a CVE that actually appears in advisory_chunks to avoid a
    # degenerate zero-hit result.
    sample = sf.execute_query("""
        SELECT cve_ids
        FROM advisory_chunks
        WHERE ARRAY_SIZE(cve_ids) > 0
        LIMIT 1
    """)
    if not sample:
        pytest.skip("no chunks carry cve_ids — cannot exercise the filter")
    target_cve = _decode_array(sample[0]["cve_ids"])[0]

    results = hybrid_search(
        query="vulnerability exploitation",
        top_k=10,
        top_n=80,
        cve_ids=[target_cve],
    )
    if not results:
        pytest.skip(f"no hybrid_search hits for cve_ids=[{target_cve}]")

    for r in results:
        ids = _decode_array(r["cve_ids"])
        assert target_cve in ids, (
            f"chunk {r['chunk_id']} was returned under cve_ids=[{target_cve}] "
            f"but its cve_ids is {ids}"
        )


def test_every_result_carries_rrf_annotations(bm25_loaded):
    """rrf_score must always be set and non-negative; at least one of
    bm25_rank/vec_rank must be populated on every hit (otherwise it
    shouldn't have made it into the fused output)."""
    from app.services.hybrid_search import hybrid_search

    results = hybrid_search(
        query="ransomware exploitation of Microsoft Exchange",
        top_k=5,
        top_n=50,
    )
    assert results, "baseline query returned zero hits"
    for r in results:
        assert r.get("rrf_score") is not None, f"missing rrf_score on {r['chunk_id']}"
        assert r["rrf_score"] > 0, f"non-positive rrf_score on {r['chunk_id']}"
        assert (r.get("bm25_rank") is not None) or (r.get("vec_rank") is not None), (
            f"chunk {r['chunk_id']} has neither bm25_rank nor vec_rank"
        )
