"""Weekly intelligence brief (stub until unstructured advisory graph exists)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter(prefix="/brief", tags=["CTI", "Brief"])


@router.get(
    "/weekly",
    summary="Weekly intelligence brief (stub)",
    description=(
        "Reserved for narrative brief using advisory nodes and edges in Neo4j. "
        "Returns a pending status until that graph slice exists."
    ),
)
async def weekly_brief() -> dict[str, Any]:
    return {
        "status": "pending",
        "message": "Advisory unstructured data is not loaded into Neo4j yet.",
    }
