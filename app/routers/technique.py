"""CTI ATT&CK technique detail from Neo4j (structured)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app.services import get_neo4j_service
from app.services.cti_graph import (
    is_valid_technique_id,
    neo4j_value_to_json,
    normalize_technique_id,
    technique_detail_cypher,
)

router = APIRouter(prefix="/technique", tags=["CTI", "Technique"])


@router.get(
    "/{technique_id}",
    summary="Get ATT&CK technique from knowledge graph",
    description="Looks up :Technique by mitre-style id (e.g. T1059, T1566.001).",
)
async def get_technique(technique_id: str) -> dict[str, Any]:
    raw = technique_id.strip()
    if not is_valid_technique_id(raw):
        raise HTTPException(status_code=400, detail="Invalid technique id format")
    tid = normalize_technique_id(raw)
    neo = get_neo4j_service()
    q, p = technique_detail_cypher(tid)
    rows = neo.execute_query(q, p)
    if not rows:
        raise HTTPException(status_code=404, detail=f"Technique {tid} not found in graph")
    row = rows[0]
    tech = neo4j_value_to_json(row.get("technique"))
    if not tech:
        raise HTTPException(status_code=404, detail=f"Technique {tid} not found in graph")
    edges = neo4j_value_to_json(row.get("edges")) or []
    return {"technique_id": tid, "technique": tech, "edges": edges}
