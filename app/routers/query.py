"""Natural-language graph query (stub until unstructured advisory data is in Neo4j)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(tags=["CTI", "Query"])


class NLQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Natural language question (reserved for future NL→Cypher)")


@router.post(
    "/query",
    summary="Natural language query (stub)",
    description=(
        "Reserved for NL→Cypher with advisory context. "
        "Returns a pending status until unstructured advisory nodes are loaded into Neo4j."
    ),
)
async def nl_query(_body: NLQueryRequest) -> dict[str, Any]:
    return {
        "status": "pending",
        "message": "Advisory unstructured data is not loaded into Neo4j yet.",
    }
