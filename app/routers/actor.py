"""CTI ATT&CK actor profile from Neo4j (structured)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app.services import get_neo4j_service
from app.services.cti_graph import actor_detail_cypher, neo4j_value_to_json

router = APIRouter(prefix="/actor", tags=["CTI", "Actor"])


@router.get(
    "/{actor_id}",
    summary="Get threat actor from knowledge graph",
    description=(
        "Looks up :Actor by name, actor_id, id, or external_id (first match wins). "
        "Returns node properties and a bounded neighborhood of relationships."
    ),
)
async def get_actor(actor_id: str) -> dict[str, Any]:
    aid = actor_id.strip()
    if not aid:
        raise HTTPException(status_code=400, detail="actor_id is required")
    neo = get_neo4j_service()
    q, p = actor_detail_cypher(aid)
    rows = neo.execute_query(q, p)
    if not rows:
        raise HTTPException(status_code=404, detail=f"Actor {aid!r} not found in graph")
    row = rows[0]
    actor = neo4j_value_to_json(row.get("actor"))
    if not actor:
        raise HTTPException(status_code=404, detail=f"Actor {aid!r} not found in graph")
    edges = neo4j_value_to_json(row.get("edges")) or []
    return {"actor_id": aid, "actor": actor, "edges": edges}
