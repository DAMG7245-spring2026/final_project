"""Graph query router: natural language -> Cypher -> Neo4j."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.text2cypher import get_text2cypher_service

router = APIRouter(prefix="/graph", tags=["graph-query"])


class GraphQueryRequest(BaseModel):
    question: str


class GraphQueryResponse(BaseModel):
    answer: str
    cypher: str | None
    row_count: int
    results: list[dict]


@router.post("/query", response_model=GraphQueryResponse)
def graph_query(req: GraphQueryRequest):
    if not req.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty")
    svc = get_text2cypher_service()
    return svc.query(req.question)
