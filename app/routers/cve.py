"""CTI CVE detail from Neo4j (structured)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app.services import get_neo4j_service
from app.services.cti_graph import (
    cve_exists_cypher,
    cve_properties_cypher,
    cve_technique_refs_cypher,
    cve_weaknesses_cypher,
    is_valid_cve_id,
    neo4j_value_to_json,
    normalize_cve_id,
)

router = APIRouter(prefix="/cve", tags=["CTI", "CVE"])


@router.get(
    "/{cve_id}",
    summary="Get CVE from knowledge graph",
    description="Returns the :CVE node (Neo4j) plus related CWE and Technique links from structured sync.",
)
async def get_cve(cve_id: str) -> dict[str, Any]:
    raw = cve_id.strip()
    if not is_valid_cve_id(raw):
        raise HTTPException(status_code=400, detail="Invalid CVE id format")
    cid = normalize_cve_id(raw)
    neo = get_neo4j_service()
    q0, p0 = cve_exists_cypher(cid)
    rows0 = neo.execute_query(q0, p0)
    if not rows0 or int(rows0[0].get("n") or 0) < 1:
        raise HTTPException(status_code=404, detail=f"CVE {cid} not found in graph")

    q1, p1 = cve_properties_cypher(cid)
    r1 = neo.execute_query(q1, p1)
    cve_props = neo4j_value_to_json((r1[0] or {}).get("cve")) if r1 else {}

    q2, p2 = cve_weaknesses_cypher(cid)
    weaknesses = [
        {
            "cwe_id": neo4j_value_to_json(row.get("cwe_id")),
            "cwe": neo4j_value_to_json(row.get("cwe")),
            "rel_props": neo4j_value_to_json(row.get("rel_props")),
        }
        for row in neo.execute_query(q2, p2)
    ]

    q3, p3 = cve_technique_refs_cypher(cid)
    techniques = [
        {
            "technique_id": neo4j_value_to_json(row.get("technique_id")),
            "technique": neo4j_value_to_json(row.get("technique")),
            "rel_props": neo4j_value_to_json(row.get("rel_props")),
        }
        for row in neo.execute_query(q3, p3)
    ]

    return {
        "cve_id": cid,
        "cve": cve_props,
        "weaknesses": weaknesses,
        "technique_references": techniques,
    }
