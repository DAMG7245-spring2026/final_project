"""Hybrid BM25 + vector search endpoint over advisory_chunks."""
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.hybrid_search import hybrid_search

router = APIRouter(prefix="/search", tags=["Search"])


class HybridSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Natural language query")
    top_k: int = Field(10, ge=1, le=100, description="Number of fused results")
    top_n: int = Field(
        50,
        ge=1,
        le=500,
        description="Candidates pulled from each retriever before fusion",
    )
    k_rrf: int = Field(60, ge=1, le=1000, description="RRF constant (paper: 60)")
    alpha: float = Field(
        0.5,
        ge=0.0,
        le=1.0,
        description="Vector weight in RRF; (1 - alpha) goes to BM25. "
                    "1.0 = vector only, 0.0 = BM25 only.",
    )
    section_names: Optional[list[str]] = None
    cve_ids: Optional[list[str]] = None
    cwe_ids: Optional[list[str]] = None
    mitre_tech_ids: Optional[list[str]] = None
    advisory_ids: Optional[list[str]] = None
    min_vector_score: Optional[float] = Field(None, ge=-1.0, le=1.0)


class HybridSearchHit(BaseModel):
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
    rrf_score: float
    bm25_rank: Optional[int]
    vec_rank: Optional[int]
    bm25_score: Optional[float]
    vector_score: Optional[float]


class HybridSearchResponse(BaseModel):
    query: str
    count: int
    alpha: float
    k_rrf: int
    results: list[HybridSearchHit]


def _coerce_array(val: Any) -> Optional[list[str]]:
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
    "/advisory-chunks/hybrid",
    response_model=HybridSearchResponse,
    summary="Hybrid BM25 + vector search over advisory chunks",
    description=(
        "Runs BM25 (in-memory index built from chunk_text) and Cortex vector "
        "search in parallel, then fuses with Reciprocal Rank Fusion. "
        "Use `alpha` to weight the two branches (0.5 = balanced)."
    ),
)
async def hybrid_search_endpoint(
    req: HybridSearchRequest,
) -> HybridSearchResponse:
    try:
        rows = hybrid_search(
            query=req.query,
            top_k=req.top_k,
            top_n=req.top_n,
            k_rrf=req.k_rrf,
            alpha=req.alpha,
            section_names=req.section_names,
            cve_ids=req.cve_ids,
            cwe_ids=req.cwe_ids,
            mitre_tech_ids=req.mitre_tech_ids,
            advisory_ids=req.advisory_ids,
            min_vector_score=req.min_vector_score,
        )
    except RuntimeError as e:
        # BM25 index not ready
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"hybrid search failed: {e}") from e

    hits = [
        HybridSearchHit(
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
            rrf_score=float(r["rrf_score"]),
            bm25_rank=r.get("bm25_rank"),
            vec_rank=r.get("vec_rank"),
            bm25_score=r.get("bm25_score"),
            vector_score=r.get("vector_score"),
        )
        for r in rows
    ]
    return HybridSearchResponse(
        query=req.query,
        count=len(hits),
        alpha=req.alpha,
        k_rrf=req.k_rrf,
        results=hits,
    )
