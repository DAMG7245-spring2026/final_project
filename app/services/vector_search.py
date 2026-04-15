"""Vector search over advisory_chunks using Snowflake Cortex."""
from typing import Any, Optional

from app.services.snowflake import get_snowflake_service

EMBED_MODEL = "snowflake-arctic-embed-l-v2.0"


def search_advisory_chunks(
    query: str,
    top_k: int = 10,
    section_names: Optional[list[str]] = None,
    cve_ids: Optional[list[str]] = None,
    cwe_ids: Optional[list[str]] = None,
    mitre_tech_ids: Optional[list[str]] = None,
    advisory_ids: Optional[list[str]] = None,
    min_score: Optional[float] = None,
) -> list[dict[str, Any]]:
    """
    Cosine-similarity search over advisory_chunks.chunk_embedding.

    Metadata filters are ANDed together. ARRAY filters (cve/cwe/mitre) use
    ARRAYS_OVERLAP, so passing ['CWE-79','CWE-89'] means "chunk mentions at
    least one of these".

    Returns rows ordered by descending similarity score.
    """
    where: list[str] = ["chunk_embedding IS NOT NULL"]
    params: list[Any] = [EMBED_MODEL, query]

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
                    SNOWFLAKE.CORTEX.EMBED_TEXT_1024(%s, %s)
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
