"""Vector search over advisory_chunks using Snowflake Cortex."""
from typing import Any, Optional

from app.services.snowflake import get_snowflake_service

EMBED_MODEL = "snowflake-arctic-embed-l-v2.0"
EMBED_DIM = 1024


def embed_query(query: str) -> list[float]:
    """Compute a single query embedding via Cortex. Useful for caching the
    vector across many searches (e.g. eval loops) so we don't pay the
    Cortex round-trip per retrieval config.
    """
    rows = get_snowflake_service().execute_query(
        "SELECT SNOWFLAKE.CORTEX.EMBED_TEXT_1024(%s, %s) AS v",
        (EMBED_MODEL, query),
    )
    return list(rows[0]["v"])


def _vec_literal(v: list[float]) -> str:
    """Format a Python float list as a Snowflake VECTOR literal. Safe to
    inline — each element is rendered as a pure numeric string.
    """
    body = ",".join(f"{x:.7f}" for x in v)
    return f"[{body}]::VECTOR(FLOAT, {EMBED_DIM})"


def search_advisory_chunks(
    query: str,
    top_k: int = 10,
    document_types: Optional[list[str]] = None,
    section_names: Optional[list[str]] = None,
    cve_ids: Optional[list[str]] = None,
    cwe_ids: Optional[list[str]] = None,
    mitre_tech_ids: Optional[list[str]] = None,
    advisory_ids: Optional[list[str]] = None,
    min_score: Optional[float] = None,
    query_embedding: Optional[list[float]] = None,
) -> list[dict[str, Any]]:
    """
    Cosine-similarity search over advisory_chunks.chunk_embedding.

    Metadata filters are ANDed together. ARRAY filters (cve/cwe/mitre) use
    ARRAYS_OVERLAP, so passing ['CWE-79','CWE-89'] means "chunk mentions at
    least one of these". `document_types` filters via the parent advisory
    (column lives on the advisories table, not advisory_chunks).

    If `query_embedding` is provided, it is used directly and Cortex is not
    called — caller is responsible for making sure the vector came from the
    same EMBED_MODEL. This is the fast path for eval loops that run the
    same query under many configs.

    Returns rows ordered by descending similarity score.
    """
    where: list[str] = ["chunk_embedding IS NOT NULL"]
    params: list[Any] = []
    if query_embedding is None:
        params.extend([EMBED_MODEL, query])

    if document_types:
        placeholders = ",".join(["%s"] * len(document_types))
        where.append(
            f"advisory_id IN (SELECT advisory_id FROM advisories "
            f"WHERE document_type IN ({placeholders}))"
        )
        params.extend(document_types)

    if section_names:
        placeholders = ",".join(["%s"] * len(section_names))
        where.append(f"section_name IN ({placeholders})")
        params.extend(section_names)

    if advisory_ids:
        placeholders = ",".join(["%s"] * len(advisory_ids))
        where.append(f"advisory_id IN ({placeholders})")
        params.extend(advisory_ids)

    if cve_ids:
        placeholders = ",".join(["%s"] * len(cve_ids))
        where.append(f"ARRAYS_OVERLAP(cve_ids, ARRAY_CONSTRUCT({placeholders}))")
        params.extend(cve_ids)

    if cwe_ids:
        placeholders = ",".join(["%s"] * len(cwe_ids))
        where.append(f"ARRAYS_OVERLAP(cwe_ids, ARRAY_CONSTRUCT({placeholders}))")
        params.extend(cwe_ids)

    if mitre_tech_ids:
        placeholders = ",".join(["%s"] * len(mitre_tech_ids))
        where.append(f"ARRAYS_OVERLAP(mitre_tech_ids, ARRAY_CONSTRUCT({placeholders}))")
        params.extend(mitre_tech_ids)

    where_sql = " AND ".join(where)
    min_score_sql = f"WHERE score >= {float(min_score)}" if min_score is not None else ""

    if query_embedding is not None:
        if len(query_embedding) != EMBED_DIM:
            raise ValueError(
                f"query_embedding must have {EMBED_DIM} dimensions, got {len(query_embedding)}"
            )
        embed_expr = _vec_literal(query_embedding)
    else:
        embed_expr = "SNOWFLAKE.CORTEX.EMBED_TEXT_1024(%s, %s)"

    sql = f"""
        WITH scored AS (
            SELECT
                chunk_id,
                advisory_id,
                chunk_index,
                section_name,
                sub_section,
                chunk_text,
                token_count,
                cve_ids,
                cwe_ids,
                mitre_tech_ids,
                VECTOR_COSINE_SIMILARITY(
                    chunk_embedding,
                    {embed_expr}
                ) AS score
            FROM advisory_chunks
            WHERE {where_sql}
        )
        SELECT * FROM scored
        {min_score_sql}
        ORDER BY score DESC
        LIMIT {int(top_k)}
    """

    svc = get_snowflake_service()
    return svc.execute_query(sql, tuple(params))
