"""Vector search endpoint over advisory_chunks."""
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.vector_search import search_advisory_chunks

router = APIRouter(prefix="/search", tags=["Search"])


class VectorSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Natural language query")
    top_k: int = Field(10, ge=1, le=100)
    section_names: Optional[list[str]] = None
    cve_ids: Optional[list[str]] = None
    cwe_ids: Optional[list[str]] = None
    mitre_tech_ids: Optional[list[str]] = None
    advisory_ids: Optional[list[str]] = None
    min_score: Optional[float] = Field(None, ge=-1.0, le=1.0)


class VectorSearchHit(BaseModel):
    chunk_id: str
    advisory_id: Optional[str]
    chunk_index: Optional[int]
    section_name: Optional[str]
    sub_section: Optional[str]
    chunk_text: Optional[str]
    token_count: Optional[int]
    cve_ids: Optional[list[str]] = None
    cwe_ids: Optional[list[str]] = None
    mitre_tech_ids: Optional[list[str]] = None
    score: float


class VectorSearchResponse(BaseModel):
    query: str
    count: int
    results: list[VectorSearchHit]


def _coerce_array(val: Any) -> Optional[list[str]]:
    """Snowflake ARRAY comes back as a JSON string; normalize to list[str]."""
    if val is None:
        return None
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        import json
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, list) else None
        except json.JSONDecodeError:
            return None
    return None


@router.post(
    "/advisory-chunks",
    response_model=VectorSearchResponse,
    summary="Vector search over advisory chunks",
    description=(
        "Runs cosine-similarity search on advisory_chunks using Snowflake Cortex "
        "(snowflake-arctic-embed-l-v2.0). Metadata filters are ANDed; ARRAY filters "
        "(cve/cwe/mitre) match if any listed value is present on the chunk."
    ),
)
async def vector_search(req: VectorSearchRequest) -> VectorSearchResponse:
    try:
        rows = search_advisory_chunks(
            query=req.query,
            top_k=req.top_k,
            section_names=req.section_names,
            cve_ids=req.cve_ids,
            cwe_ids=req.cwe_ids,
            mitre_tech_ids=req.mitre_tech_ids,
            advisory_ids=req.advisory_ids,
            min_score=req.min_score,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"search failed: {e}") from e

    hits = [
        VectorSearchHit(
            chunk_id=r["chunk_id"],
            advisory_id=r.get("advisory_id"),
            chunk_index=r.get("chunk_index"),
            section_name=r.get("section_name"),
            sub_section=r.get("sub_section"),
            chunk_text=r.get("chunk_text"),
            token_count=r.get("token_count"),
            cve_ids=_coerce_array(r.get("cve_ids")),
            cwe_ids=_coerce_array(r.get("cwe_ids")),
            mitre_tech_ids=_coerce_array(r.get("mitre_tech_ids")),
            score=float(r["score"]) if r.get("score") is not None else 0.0,
        )
        for r in rows
    ]
    return VectorSearchResponse(query=req.query, count=len(hits), results=hits)
