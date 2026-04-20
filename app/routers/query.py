"""Natural-language RAG query endpoint backed by the LLM route-picker.

A single question is classified into one of three retrieval strategies
(graph / text / both) and the best answer is returned. The `force_route`
and `disable_fallback` fields are the hooks the AI-as-judge eval harness
uses to run the same question through each route head-to-head.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.rag_router import get_rag_router_service

router = APIRouter(tags=["CTI", "Query"])


class QueryRequest(BaseModel):
    question: str = Field(..., min_length=1)
    force_route: Literal["graph", "text", "both"] | None = Field(
        None,
        description=(
            "Bypass the LLM classifier and run a specific route. "
            "Used by the AI-as-judge eval harness to compare routes "
            "head-to-head on the same question."
        ),
    )
    disable_fallback: bool = Field(
        False,
        description=(
            "When true, skip the graph→text zero-row fallback. "
            "Set this during eval to measure the chosen route's "
            "standalone performance."
        ),
    )


class QueryResponse(BaseModel):
    answer: str
    route: Literal["graph", "text", "both"]
    route_reasoning: str | None = None
    route_was_forced: bool = False
    fallback_triggered: bool = False
    cypher: str | None = None
    graph_row_count: int | None = None
    graph_results: list[dict] | None = None
    chunks: list[dict] | None = None


@router.post(
    "/query",
    response_model=QueryResponse,
    summary="Natural-language RAG query with automatic route selection",
    description=(
        "Routes the question to Text2Cypher (graph), hybrid_search (text), "
        "or both in parallel, then synthesizes a single answer. Pass "
        "`force_route` to bypass the classifier (eval-harness hook)."
    ),
)
def nl_query(req: QueryRequest) -> QueryResponse:
    if not req.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty")
    svc = get_rag_router_service()
    result = svc.answer(
        req.question,
        force_route=req.force_route,
        disable_fallback=req.disable_fallback,
    )
    return QueryResponse(**result)
