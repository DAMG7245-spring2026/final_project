"""Weekly CVE threat-intel brief endpoint.

Orchestrator-workers pipeline that consumes ``/weekly-digest``'s structured
rows, enriches each CVE with one RAG call against the graph + advisory
corpus, and stitches the result into a markdown brief. See
``app/services/weekly_brief.py`` for the architecture notes.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.services.weekly_brief import WeeklyBrief, generate_weekly_brief
from app.services.weekly_digest import (
    DEFAULT_MAX_TIER,
    DEFAULT_NEWLY_ADDED_KEV_N,
    DEFAULT_TOP_N,
)

router = APIRouter(prefix="/weekly-brief", tags=["CTI", "Brief"])


@router.get(
    "",
    response_model=WeeklyBrief,
    summary="Generate weekly CVE threat-intel brief",
    description=(
        "Runs the orchestrator-workers pipeline end to end:\n\n"
        "1. Pull the tier-ranked digest (same SQL as `/weekly-digest`).\n"
        "2. Fan out one RAG call per unique CVE "
        "(`rag_router.answer(force_route='both')`), concurrent and bounded "
        "at 8 workers via `asyncio.Semaphore`.\n"
        "3. Single synthesis LLM call stitches summary + evidence into a "
        "markdown brief with three mandatory sections "
        "(Headline numbers / This week's newly exploited / Most dangerous "
        "active threats).\n\n"
        "Typical wall clock: 20-40 seconds for 10-15 CVEs. The response "
        "includes the digest snapshot, per-CVE evidence, and synthesis "
        "token / cost counters for traceability."
    ),
)
async def weekly_brief_endpoint(
    window_start: Optional[date] = Query(
        None,
        description=(
            "Inclusive start date, ISO `YYYY-MM-DD`. "
            "Defaults to `window_end - 7d`."
        ),
    ),
    window_end: Optional[date] = Query(
        None,
        description="Exclusive end date, ISO `YYYY-MM-DD`. Defaults to today.",
    ),
    limit: int = Query(
        DEFAULT_TOP_N,
        ge=1,
        le=50,
        description="Max rows in the danger-ranked top list.",
    ),
    max_tier: int = Query(
        DEFAULT_MAX_TIER,
        ge=1,
        le=5,
        description="Highest tier number to include (1 = strongest signal).",
    ),
    newly_added_limit: int = Query(
        DEFAULT_NEWLY_ADDED_KEV_N,
        ge=1,
        le=50,
        description="Max rows in the 'newly added KEV this week' feed.",
    ),
    ingested_after: Optional[datetime] = Query(
        None,
        description=(
            "Only include CVE rows whose `ingested_at` timestamp (first load "
            "into Snowflake) is >= this value. ISO `YYYY-MM-DD` or "
            "`YYYY-MM-DDTHH:MM:SS`. Earliest CVE ingestion in this deployment "
            "is 2026-04-15 13:56:25.559."
        ),
    ),
) -> WeeklyBrief:
    try:
        return await generate_weekly_brief(
            window_start=window_start,
            window_end=window_end,
            limit=limit,
            max_tier=max_tier,
            newly_added_limit=newly_added_limit,
            ingested_after=ingested_after,
        )
    except ValueError as e:
        # Raised when window_start >= window_end (from _resolve_window).
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"weekly brief failed: {e}"
        ) from e
