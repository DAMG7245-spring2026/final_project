"""Weekly CVE digest endpoint — lets callers inspect the shape the brief
orchestrator will consume (summary counts + tier-ranked top CVEs).

Pure read-only, no LLM. Ranking is done in SQL inside
``app.services.weekly_digest``; this router only transports the result and
documents it in OpenAPI.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from app.services.weekly_digest import (
    DEFAULT_MAX_TIER,
    DEFAULT_NEWLY_ADDED_KEV_N,
    DEFAULT_TOP_N,
    WeeklyCve,
    WeeklyDigestSummary,
    weekly_digest as _weekly_digest,
)

router = APIRouter(prefix="/weekly-digest", tags=["CTI", "Brief"])


# Example payload embedded in the OpenAPI response schema so /docs shows
# exactly what the brief orchestrator will receive.
_EXAMPLE_RESPONSE = {
    "summary": {
        "window_start": "2026-04-14",
        "window_end": "2026-04-21",
        "total_modified": 412,
        "newly_published": 187,
        "critical_count": 23,
        "kev_added_count": 3,
        "kev_ransomware_count": 2,
        "has_exploit_ref_count": 41,
    },
    "top_cves": [
        {
            "cve_id": "CVE-2026-12345",
            "tier": 1,
            "tier_reason": "KEV + known ransomware use",
            "description_en": "Remote code execution in ExampleCorp Gateway ...",
            "vuln_status": "ANALYZED",
            "published_date": "2026-04-15",
            "last_modified": "2026-04-20T14:23:11",
            "cvss_version": "3.1",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "exploitability_score": 3.9,
            "impact_score": 5.9,
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "has_exploit_ref": True,
            "is_kev": True,
            "kev_date_added": "2026-04-18",
            "kev_ransomware_use": "Known",
            "kev_required_action": "Apply mitigations per vendor instructions ...",
            "kev_due_date": "2026-05-09",
            "kev_vendor_project": "ExampleCorp",
            "kev_product": "Gateway",
        },
        {
            "cve_id": "CVE-2026-22222",
            "tier": 3,
            "tier_reason": "public exploit reference + CVSS >= 9",
            "description_en": "Authentication bypass in Acme VPN ...",
            "vuln_status": "ANALYZED",
            "published_date": "2026-04-17",
            "last_modified": "2026-04-19T08:10:00",
            "cvss_version": "3.1",
            "cvss_score": 9.1,
            "cvss_severity": "CRITICAL",
            "exploitability_score": 3.9,
            "impact_score": 5.2,
            "confidentiality_impact": "HIGH",
            "integrity_impact": "LOW",
            "has_exploit_ref": True,
            "is_kev": False,
            "kev_date_added": None,
            "kev_ransomware_use": None,
            "kev_required_action": None,
            "kev_due_date": None,
            "kev_vendor_project": None,
            "kev_product": None,
        },
    ],
    "newly_added_kev": [
        {
            "cve_id": "CVE-2026-33333",
            "tier": 2,
            "tier_reason": "KEV added this week",
            "description_en": "Path traversal in FictionalCorp Firewall ...",
            "vuln_status": "ANALYZED",
            "published_date": "2026-03-02",
            "last_modified": "2026-04-19T10:01:00",
            "cvss_version": "3.1",
            "cvss_score": 8.8,
            "cvss_severity": "HIGH",
            "exploitability_score": 2.8,
            "impact_score": 5.9,
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "has_exploit_ref": False,
            "is_kev": True,
            "kev_date_added": "2026-04-19",
            "kev_ransomware_use": "Known",
            "kev_required_action": "Apply updates per vendor instructions.",
            "kev_due_date": "2026-05-10",
            "kev_vendor_project": "FictionalCorp",
            "kev_product": "Firewall",
        }
    ],
}


class WeeklyDigestResponse(BaseModel):
    """Envelope the weekly-brief orchestrator consumes.

    - ``summary``: headline counts (what goes above the fold in the brief).
    - ``top_cves``: tier-ranked CVEs for the body, already sorted by signal
      strength so the orchestrator can iterate linearly.
    - ``newly_added_kev``: CVEs added to CISA KEV within the window, queried
      independently of ``top_cves`` so Tier 1's evergreen entries cannot
      starve this feed. Orchestrator renders this as its own "This week's
      newly exploited" section.
    """

    summary: WeeklyDigestSummary
    top_cves: list[WeeklyCve]
    newly_added_kev: list[WeeklyCve]

    model_config = ConfigDict(json_schema_extra={"example": _EXAMPLE_RESPONSE})


@router.get(
    "",
    response_model=WeeklyDigestResponse,
    summary="Weekly CVE digest: summary + tier-ranked top CVEs",
    description=(
        "Tier-ranked snapshot of ``cve_records`` for the brief pipeline. "
        "Ranking is pure SQL (no LLM). Window is half-open ``[start, end)``; "
        "defaults to the past 7 days ending today.\n\n"
        "**Tiers** (lower = higher signal):\n\n"
        "| Tier | Rule |\n"
        "| --- | --- |\n"
        "| 1 | `is_kev = TRUE` AND `kev_ransomware_use = 'Known'` |\n"
        "| 2 | `is_kev = TRUE` AND `kev_date_added` in window (newly added KEV) |\n"
        "| 3 | `has_exploit_ref = TRUE` AND `cvss_score >= 9.0` |\n"
        "| 4 | `cvss_severity = 'CRITICAL'` AND `confidentiality_impact = 'HIGH'` |\n"
        "| 5 | everything else modified in the window (excluded unless `max_tier=5`) |\n\n"
        "Rows with `vuln_status = 'REJECTED'` are always excluded.\n\n"
        "**Examples**\n"
        "```\n"
        "# default: past 7 days, tier 1-4, top 10\n"
        "GET /weekly-digest\n\n"
        "# CISO-friendly version: top 5, tier 1-4\n"
        "GET /weekly-digest?limit=5\n\n"
        "# explicit window + include tier 5 tail\n"
        "GET /weekly-digest?window_start=2026-04-14&window_end=2026-04-21&max_tier=5&limit=50\n"
        "```"
    ),
)
async def weekly_digest_endpoint(
    window_start: Optional[date] = Query(
        None,
        description=(
            "Inclusive start date, ISO `YYYY-MM-DD`. "
            "Defaults to `window_end - 7d`."
        ),
    ),
    window_end: Optional[date] = Query(
        None,
        description=(
            "Exclusive end date, ISO `YYYY-MM-DD`. "
            "Defaults to today (UTC by server clock)."
        ),
    ),
    limit: int = Query(
        DEFAULT_TOP_N,
        ge=1,
        le=100,
        description="Max top CVEs to return. Default 10; brief usually uses 5.",
    ),
    max_tier: int = Query(
        DEFAULT_MAX_TIER,
        ge=1,
        le=5,
        description=(
            "Highest tier number to include (1 = strongest signal). "
            "Pass 5 to include the tail."
        ),
    ),
    newly_added_limit: int = Query(
        DEFAULT_NEWLY_ADDED_KEV_N,
        ge=1,
        le=50,
        description=(
            "Max rows in the independent 'newly added KEV this week' feed. "
            "Queried separately from `top_cves` so Tier 1 evergreen entries "
            "cannot starve it."
        ),
    ),
) -> WeeklyDigestResponse:
    try:
        result = _weekly_digest(
            window_start=window_start,
            window_end=window_end,
            limit=limit,
            max_tier=max_tier,
            newly_added_limit=newly_added_limit,
        )
    except ValueError as e:
        # Raised by _resolve_window when window_start >= window_end.
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"weekly digest failed: {e}"
        ) from e
    return WeeklyDigestResponse(
        summary=result["summary"],
        top_cves=result["top_cves"],
        newly_added_kev=result["newly_added_kev"],
    )
