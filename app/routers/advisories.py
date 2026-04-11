"""Advisories endpoints."""
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query

from app.services import get_snowflake_service

router = APIRouter(prefix="/advisories", tags=["Advisories"])

ADVISORY_COLUMNS = [
    "advisory_id",
    "title",
    "url",
    "s3_raw_path",
    "published_date",
    "advisory_type",
    "document_type",
    "co_authors",
    "threat_actors",
    "cve_ids_mentioned",
    "mitre_ids_mentioned",
    "triplets_extracted",
    "loaded_to_neo4j",
    "ingested_at",
]

ALLOWED_DOCUMENT_TYPES = {
    "MAR",
    "ANALYSIS_REPORT",
    "JOINT_CSA",
    "STOPRANSOMWARE",
    "CSA",
    "IR_LESSONS",
}


def _serialize(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in row.items():
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


@router.get("", summary="List advisories filtered by document_type")
async def list_advisories(
    document_type: Optional[str] = Query(
        None, description="Filter by document_type (e.g. MAR, CSA, JOINT_CSA)"
    ),
    limit: int = Query(5, ge=1, le=50),
) -> dict[str, Any]:
    if document_type and document_type not in ALLOWED_DOCUMENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"document_type must be one of {sorted(ALLOWED_DOCUMENT_TYPES)}",
        )

    svc = get_snowflake_service()
    cols = ", ".join(ADVISORY_COLUMNS)

    if document_type:
        query = f"""
            SELECT {cols}
            FROM advisories
            WHERE document_type = %s
            ORDER BY published_date DESC NULLS LAST, ingested_at DESC
            LIMIT {int(limit)}
        """
        rows = svc.execute_query(query, (document_type,))
    else:
        query = f"""
            SELECT {cols}
            FROM advisories
            ORDER BY published_date DESC NULLS LAST, ingested_at DESC
            LIMIT {int(limit)}
        """
        rows = svc.execute_query(query)

    return {
        "columns": ADVISORY_COLUMNS,
        "count": len(rows),
        "rows": [_serialize(r) for r in rows],
    }


CHUNK_COLUMNS = [
    "chunk_id",
    "advisory_id",
    "chunk_index",
    "section_name",
    "sub_section",
    "chunk_text",
    "token_count",
    "content_hash",
    "cve_ids",
    "cwe_ids",
    "mitre_tech_ids",
    "triplets_extracted",
    "extraction_model",
    "extracted_at",
    "ingested_at",
]


@router.get("/chunks", summary="List advisory chunks filtered by document_type")
async def list_advisory_chunks(
    document_type: Optional[str] = Query(
        None, description="Filter by parent advisory document_type"
    ),
    limit: int = Query(5, ge=1, le=50),
) -> dict[str, Any]:
    if document_type and document_type not in ALLOWED_DOCUMENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"document_type must be one of {sorted(ALLOWED_DOCUMENT_TYPES)}",
        )

    svc = get_snowflake_service()
    cols = ", ".join(f"c.{col}" for col in CHUNK_COLUMNS)

    if document_type:
        query = f"""
            SELECT {cols}
            FROM advisory_chunks c
            JOIN advisories a ON a.advisory_id = c.advisory_id
            WHERE a.document_type = %s
            ORDER BY c.ingested_at DESC, c.chunk_index ASC
            LIMIT {int(limit)}
        """
        rows = svc.execute_query(query, (document_type,))
    else:
        query = f"""
            SELECT {cols}
            FROM advisory_chunks c
            ORDER BY c.ingested_at DESC, c.chunk_index ASC
            LIMIT {int(limit)}
        """
        rows = svc.execute_query(query)

    return {
        "columns": CHUNK_COLUMNS,
        "count": len(rows),
        "rows": [_serialize(r) for r in rows],
    }
