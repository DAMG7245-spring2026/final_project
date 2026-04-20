"""Structured attack-path traversal in Neo4j."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query

from app.services import get_neo4j_service
from app.services.cti_graph import (
    actor_exists_cypher,
    attack_paths_cypher,
    cve_exists_cypher,
    is_valid_cve_id,
    is_valid_technique_id,
    neo4j_value_to_json,
    normalize_cve_id,
    normalize_technique_id,
    technique_exists_cypher,
)

router = APIRouter(prefix="/graph", tags=["CTI", "Graph"])


@router.get(
    "/attack-path",
    summary="Bounded paths over CVE, Technique, Actor, CWE",
    description=(
        "Exactly one of `from_cve`, `from_actor`, or `from_technique` must be set. "
        "Returns up to `limit` paths of length up to `max_hops` through the structured graph."
    ),
)
async def get_attack_path(
    from_cve: Optional[str] = None,
    from_actor: Optional[str] = None,
    from_technique: Optional[str] = None,
    max_hops: int = Query(3, ge=1, le=6),
    limit: int = Query(10, ge=1, le=25),
) -> dict[str, Any]:
    n_provided = sum(
        1 for v in (from_cve, from_actor, from_technique) if v is not None and str(v).strip()
    )
    if n_provided != 1:
        raise HTTPException(
            status_code=400,
            detail="Provide exactly one of: from_cve, from_actor, from_technique",
        )

    kind: str
    value: str
    if from_cve is not None and str(from_cve).strip():
        raw = from_cve.strip()
        if not is_valid_cve_id(raw):
            raise HTTPException(status_code=400, detail="Invalid from_cve format")
        kind, value = "cve", normalize_cve_id(raw)
    elif from_technique is not None and str(from_technique).strip():
        raw = from_technique.strip()
        if not is_valid_technique_id(raw):
            raise HTTPException(status_code=400, detail="Invalid from_technique format")
        kind, value = "technique", normalize_technique_id(raw)
    else:
        av = (from_actor or "").strip()
        if not av:
            raise HTTPException(status_code=400, detail="from_actor is empty")
        kind, value = "actor", av

    neo = get_neo4j_service()
    if kind == "cve":
        qx, px = cve_exists_cypher(value)
    elif kind == "technique":
        qx, px = technique_exists_cypher(value)
    else:
        qx, px = actor_exists_cypher(value)
    ex = neo.execute_query(qx, px)
    if not ex or int(ex[0].get("n") or 0) < 1:
        raise HTTPException(
            status_code=404,
            detail=f"No {kind} start node {value!r} found in graph",
        )

    q, p = attack_paths_cypher(kind=kind, value=value, max_hops=max_hops, limit=limit)
    rows = neo.execute_query(q, p)
    paths_raw = (rows[0] or {}).get("paths") if rows else None
    paths = neo4j_value_to_json(paths_raw) or []

    return {
        "start": {"kind": kind, "value": value},
        "max_hops": max_hops,
        "limit": limit,
        "path_count": len(paths),
        "paths": paths,
    }
