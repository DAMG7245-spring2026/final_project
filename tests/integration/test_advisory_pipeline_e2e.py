"""Validate the chunker + embedding contract against live Snowflake state.

The retrieval stack assumes two invariants about CISA advisory ingestion:

  1. ``chunk_advisory`` is deterministic. Running it on the S3 HTML of an
     advisory must reproduce — bit-for-bit — the ``content_hash`` and
     extracted ID arrays already stored in ``advisory_chunks``. Any code
     change that shifts how we split, normalize sections, or extract
     CVE/CWE/MITRE IDs will fail this test.

  2. Every persisted ``chunk_embedding`` is a 1024-dim Cortex vector —
     the shape ``app.services.vector_search`` and ``hybrid_search`` both
     rely on.

Source of truth: the advisory picked by the ``ground_truth_advisory``
fixture. No seeding, no mocking.
"""
from __future__ import annotations

import json

import pytest

from ingestion.advisory.chunker_v2 import chunk_advisory

pytestmark = pytest.mark.integration


def _decode_array(col) -> list[str]:
    """Snowflake ARRAY columns come back as JSON strings in dict-cursor mode."""
    if col is None:
        return []
    if isinstance(col, str):
        return json.loads(col)
    return list(col)


def test_rechunking_reproduces_persisted_content_hashes(
    ground_truth_advisory, advisory_html,
):
    """Re-run chunk_advisory on the S3 HTML; every persisted row must be
    reproduced with the same content_hash. Catches any accidental change
    to the chunker's text-normalization pipeline."""
    from app.services.snowflake import get_snowflake_service
    sf = get_snowflake_service()
    aid = ground_truth_advisory["advisory_id"]

    persisted = sf.execute_query(
        "SELECT chunk_index, section_name, sub_section, token_count, content_hash, "
        "       cve_ids, cwe_ids, mitre_tech_ids "
        "FROM advisory_chunks WHERE advisory_id = %s ORDER BY chunk_index",
        (aid,),
    )
    assert persisted, f"ground truth advisory {aid} has no chunks persisted"

    rechunked = chunk_advisory(aid, ground_truth_advisory["document_type"], advisory_html)

    assert len(rechunked) == len(persisted), (
        f"chunk count drift for {aid}: "
        f"persisted={len(persisted)}, rechunked={len(rechunked)}. "
        "Did the chunker's splitting logic change?"
    )

    drifted: list[str] = []
    for p, r in zip(persisted, rechunked):
        assert p["chunk_index"] == r.chunk_index
        if p["content_hash"] != r.content_hash:
            drifted.append(
                f"idx={r.chunk_index} section={r.section_name!r} "
                f"persisted={p['content_hash'][:12]} rechunked={r.content_hash[:12]}"
            )
    assert not drifted, "content_hash drift:\n  " + "\n  ".join(drifted)


def test_rechunking_reproduces_section_and_id_extraction(
    ground_truth_advisory, advisory_html,
):
    """Section normalization and CVE/CWE/MITRE extraction must round-trip."""
    from app.services.snowflake import get_snowflake_service
    sf = get_snowflake_service()
    aid = ground_truth_advisory["advisory_id"]

    persisted = sf.execute_query(
        "SELECT chunk_index, section_name, cve_ids, cwe_ids, mitre_tech_ids "
        "FROM advisory_chunks WHERE advisory_id = %s ORDER BY chunk_index",
        (aid,),
    )
    rechunked = chunk_advisory(aid, ground_truth_advisory["document_type"], advisory_html)
    assert len(rechunked) == len(persisted)

    for p, r in zip(persisted, rechunked):
        assert p["section_name"] == r.section_name, (
            f"section name drift at chunk_index={r.chunk_index}: "
            f"persisted={p['section_name']!r}, rechunked={r.section_name!r}"
        )
        assert set(_decode_array(p["cve_ids"])) == set(r.cve_ids), (
            f"cve_ids drift at chunk_index={r.chunk_index}"
        )
        assert set(_decode_array(p["cwe_ids"])) == set(r.cwe_ids), (
            f"cwe_ids drift at chunk_index={r.chunk_index}"
        )
        assert set(_decode_array(p["mitre_tech_ids"])) == set(r.mitre_tech_ids), (
            f"mitre_tech_ids drift at chunk_index={r.chunk_index}"
        )


def test_all_persisted_chunk_embeddings_are_1024_dim(ground_truth_advisory):
    """``app.services.vector_search.EMBED_DIM == 1024``. Any row that
    violates this would crash the vector branch of hybrid search."""
    from app.services.snowflake import get_snowflake_service
    sf = get_snowflake_service()
    aid = ground_truth_advisory["advisory_id"]

    rows = sf.execute_query(
        "SELECT chunk_id, ARRAY_SIZE(chunk_embedding::ARRAY) AS dim "
        "FROM advisory_chunks "
        "WHERE advisory_id = %s AND chunk_embedding IS NOT NULL",
        (aid,),
    )
    assert rows, "no embedded chunks for ground-truth advisory"
    bad = [r for r in rows if r["dim"] != 1024]
    assert not bad, f"chunks with non-1024 embedding dim: {bad}"
