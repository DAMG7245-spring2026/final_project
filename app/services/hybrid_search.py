"""Hybrid BM25 + vector search over advisory_chunks with RRF fusion.

Pulls ranked lists from:
  - BM25Index (in-memory, built from chunk_text)
  - vector_search.search_advisory_chunks (Snowflake Cortex cosine)

Fuses them with Reciprocal Rank Fusion:

    rrf(d) = sum over retrievers of  weight_r / (k + rank_r(d))

where weights come from `alpha` (alpha -> vector, 1 - alpha -> bm25).

Metadata filters (document_types / section_names / cve_ids / cwe_ids /
mitre_tech_ids / advisory_ids) are applied to both the vector branch and
(via an enrichment query) the BM25 branch, so the filter semantics match
`vector_search`. Specific entity names (CVE/CWE/MITRE/advisory IDs) are
left to BM25 text matching unless a caller passes them explicitly —
document_type is the primary routing signal for AI-agent use via MCP.
"""

from typing import Any, Optional

from app.services.bm25_index import get_bm25_index
from app.services.snowflake import get_snowflake_service
from app.services.vector_search import search_advisory_chunks


def _fetch_chunks_by_ids(
    chunk_ids: list[str],
    document_types: Optional[list[str]] = None,
    section_names: Optional[list[str]] = None,
    cve_ids: Optional[list[str]] = None,
    cwe_ids: Optional[list[str]] = None,
    mitre_tech_ids: Optional[list[str]] = None,
    advisory_ids: Optional[list[str]] = None,
) -> dict[str, dict[str, Any]]:
    """Fetch full chunk rows for the given chunk_ids, applying the same
    metadata filters as vector_search. Returns {chunk_id: row}.

    Used to enrich BM25-only hits after RRF fusion.
    """
    if not chunk_ids:
        return {}

    where: list[str] = []
    params: list[Any] = []

    placeholders = ",".join(["%s"] * len(chunk_ids))
    where.append(f"chunk_id IN ({placeholders})")
    params.extend(chunk_ids)

    if document_types:
        ph = ",".join(["%s"] * len(document_types))
        where.append(
            f"advisory_id IN (SELECT advisory_id FROM advisories "
            f"WHERE document_type IN ({ph}))"
        )
        params.extend(document_types)

    if section_names:
        ph = ",".join(["%s"] * len(section_names))
        where.append(f"section_name IN ({ph})")
        params.extend(section_names)

    if advisory_ids:
        ph = ",".join(["%s"] * len(advisory_ids))
        where.append(f"advisory_id IN ({ph})")
        params.extend(advisory_ids)

    if cve_ids:
        ph = ",".join(["%s"] * len(cve_ids))
        where.append(f"ARRAYS_OVERLAP(cve_ids, ARRAY_CONSTRUCT({ph}))")
        params.extend(cve_ids)

    if cwe_ids:
        ph = ",".join(["%s"] * len(cwe_ids))
        where.append(f"ARRAYS_OVERLAP(cwe_ids, ARRAY_CONSTRUCT({ph}))")
        params.extend(cwe_ids)

    if mitre_tech_ids:
        ph = ",".join(["%s"] * len(mitre_tech_ids))
        where.append(f"ARRAYS_OVERLAP(mitre_tech_ids, ARRAY_CONSTRUCT({ph}))")
        params.extend(mitre_tech_ids)

    sql = f"""
        SELECT chunk_id, advisory_id, chunk_index, section_name, sub_section,
               chunk_text, token_count, cve_ids, cwe_ids, mitre_tech_ids
          FROM advisory_chunks
         WHERE {" AND ".join(where)}
    """
    svc = get_snowflake_service()
    rows = svc.execute_query(sql, tuple(params))
    return {r["chunk_id"]: r for r in rows}


def hybrid_search(
    query: str,
    top_k: int = 10,
    top_n: int = 50,
    k_rrf: int = 60,
    alpha: float = 0.2,
    document_types: Optional[list[str]] = None,
    section_names: Optional[list[str]] = None,
    cve_ids: Optional[list[str]] = None,
    cwe_ids: Optional[list[str]] = None,
    mitre_tech_ids: Optional[list[str]] = None,
    advisory_ids: Optional[list[str]] = None,
    min_vector_score: Optional[float] = None,
    query_embedding: Optional[list[float]] = None,
) -> list[dict[str, Any]]:
    """Hybrid BM25 + vector search with Reciprocal Rank Fusion.

    Args:
        query: natural-language query
        top_k: number of fused results to return
        top_n: candidates to pull from each retriever before fusion
        k_rrf: RRF constant (paper default 60)
        alpha: weight on vector branch; (1 - alpha) goes to BM25.
               alpha=1.0 -> vector only, alpha=0.0 -> BM25 only.
        document_types: primary routing filter (MAR / ANALYSIS_REPORT /
            JOINT_CSA / STOPRANSOMWARE / IR_LESSONS / CSA). Intended for
            an AI agent to narrow search to the right advisory category.
        *_ids / section_names / min_vector_score: same semantics as vector_search
    """
    alpha = max(0.0, min(1.0, alpha))

    # 1. BM25 branch
    bm25_hits = get_bm25_index().search(query, top_n=top_n)
    bm25_rank: dict[str, int] = {h.chunk_id: h.rank for h in bm25_hits}
    bm25_score: dict[str, float] = {h.chunk_id: h.score for h in bm25_hits}

    # 2. Vector branch (reuses existing service + filters).
    # `query_embedding` short-circuits the Cortex round-trip; useful for
    # eval loops that run the same query under many configs.
    vec_rows = search_advisory_chunks(
        query=query,
        top_k=top_n,
        document_types=document_types,
        section_names=section_names,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        mitre_tech_ids=mitre_tech_ids,
        advisory_ids=advisory_ids,
        min_score=min_vector_score,
        query_embedding=query_embedding,
    )
    vec_rank: dict[str, int] = {r["chunk_id"]: i + 1 for i, r in enumerate(vec_rows)}
    vec_score: dict[str, float] = {
        r["chunk_id"]: float(r["score"]) if r.get("score") is not None else 0.0
        for r in vec_rows
    }
    row_by_id: dict[str, dict[str, Any]] = {r["chunk_id"]: r for r in vec_rows}

    # 3. RRF fusion
    all_ids = set(bm25_rank) | set(vec_rank)
    fused: list[tuple[str, float]] = []
    for cid in all_ids:
        score = 0.0
        if cid in bm25_rank:
            score += (1.0 - alpha) / (k_rrf + bm25_rank[cid])
        if cid in vec_rank:
            score += alpha / (k_rrf + vec_rank[cid])
        fused.append((cid, score))
    fused.sort(key=lambda x: x[1], reverse=True)

    # 4. Enrich BM25-only hits (and apply filters to them).
    # Over-fetch a bit so filter drops don't shrink us below top_k.
    fetch_pool = fused[: top_k * 3]
    missing = [cid for cid, _ in fetch_pool if cid not in row_by_id]
    if missing:
        enriched = _fetch_chunks_by_ids(
            missing,
            document_types=document_types,
            section_names=section_names,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            mitre_tech_ids=mitre_tech_ids,
            advisory_ids=advisory_ids,
        )
        row_by_id.update(enriched)

    # 5. Build final ordered results, dropping ids that failed enrichment
    # (either filtered out or not found).
    results: list[dict[str, Any]] = []
    for cid, rrf_score in fused:
        row = row_by_id.get(cid)
        if row is None:
            continue
        out = dict(row)
        out["rrf_score"] = rrf_score
        out["bm25_rank"] = bm25_rank.get(cid)
        out["vec_rank"] = vec_rank.get(cid)
        out["bm25_score"] = bm25_score.get(cid)
        out["vector_score"] = vec_score.get(cid)
        results.append(out)
        if len(results) >= top_k:
            break
    return results
