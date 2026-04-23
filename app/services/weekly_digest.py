"""Weekly CVE digest: tier-ranked top CVEs from ``cve_records`` for the weekly brief.

Ranking is pure SQL — the LLM writes narrative, not priorities. The tier logic
encodes "what a CISO actually wants to hear first":

  T1  is_kev = TRUE AND kev_ransomware_use = 'Known'
          → actively exploited and tied to ransomware campaigns.
  T2  is_kev = TRUE AND kev_date_added in window
          → freshly added to CISA KEV this week (new confirmed in-the-wild use).
  T3  has_exploit_ref = TRUE AND cvss_score >= 9.0
          → critical and a public exploit/PoC is already referenced by NVD.
  T4  cvss_severity = 'CRITICAL' AND confidentiality_impact = 'HIGH'
          → worst-case severity on the confidentiality axis, even without KEV.
  T5  anything else modified in the window (excluded from the brief by default).

Within a tier, rows sort by
``kev_date_added DESC, cvss_score DESC, exploitability_score DESC,
impact_score DESC, last_modified DESC``.

The leading ``kev_date_added DESC`` makes freshly-added KEV entries bubble up
within T1/T2, so the brief reflects *this week's news* instead of whichever
decade-old KEV CVE happens to have been re-analyzed by NVD in the window.
For non-KEV rows (T3/T4) the key is NULL — they fall through to the
CVSS-based tiebreakers unchanged.

``vuln_status = 'REJECTED'`` rows are always excluded.

Window: the caller passes ``window_start`` / ``window_end`` as ``date`` objects.
The default window is the past 7 days ending today. The semantic of "in the
window" is:

    last_modified ∈ [window_start, window_end)
    OR (is_kev AND kev_date_added ∈ [window_start, window_end))

— so a CVE that was published years ago but just got added to KEV this week
still surfaces.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

import structlog
from pydantic import BaseModel

from app.services.snowflake import get_snowflake_service

log = structlog.get_logger(__name__)


DEFAULT_TOP_N = 10
DEFAULT_WINDOW_DAYS = 7
DEFAULT_MAX_TIER = 4
DEFAULT_NEWLY_ADDED_KEV_N = 5


class WeeklyCve(BaseModel):
    """One CVE row, shaped for the weekly-brief orchestrator."""

    cve_id: str
    tier: int
    tier_reason: str
    # Core identity
    description_en: str | None = None
    vuln_status: str | None = None
    published_date: date | None = None
    last_modified: datetime | None = None
    # CVSS
    cvss_version: str | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    exploitability_score: float | None = None
    impact_score: float | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    # Exploit / KEV
    has_exploit_ref: bool = False
    is_kev: bool = False
    kev_date_added: date | None = None
    kev_ransomware_use: str | None = None
    kev_required_action: str | None = None
    kev_due_date: date | None = None
    kev_vendor_project: str | None = None
    kev_product: str | None = None


class WeeklyDigestSummary(BaseModel):
    """Headline counts for the week — sits above the top-N list in the brief."""

    window_start: date
    window_end: date
    total_modified: int
    newly_published: int
    critical_count: int
    kev_added_count: int
    kev_ransomware_count: int
    has_exploit_ref_count: int


# -- SQL --------------------------------------------------------------------

# The tier CASE expression is repeated in SELECT (to return `tier`/`tier_reason`)
# and in WHERE (to cap at max_tier). Snowflake's query optimizer will fold them.
_TOP_CVES_SQL = """
WITH window_rows AS (
    SELECT *
    FROM cve_records
    WHERE vuln_status <> 'REJECTED'
      AND (
          (last_modified >= %(start_ts)s AND last_modified < %(end_ts)s)
          OR (is_kev = TRUE
              AND kev_date_added >= %(start_date)s
              AND kev_date_added < %(end_date)s)
      )
),
tiered AS (
    SELECT
        *,
        CASE
            WHEN is_kev = TRUE AND kev_ransomware_use = 'Known' THEN 1
            WHEN is_kev = TRUE
                 AND kev_date_added >= %(start_date)s
                 AND kev_date_added < %(end_date)s THEN 2
            WHEN has_exploit_ref = TRUE AND cvss_score >= 9.0 THEN 3
            WHEN cvss_severity = 'CRITICAL'
                 AND confidentiality_impact = 'HIGH' THEN 4
            ELSE 5
        END AS tier,
        CASE
            WHEN is_kev = TRUE AND kev_ransomware_use = 'Known'
                THEN 'KEV + known ransomware use'
            WHEN is_kev = TRUE
                 AND kev_date_added >= %(start_date)s
                 AND kev_date_added < %(end_date)s
                THEN 'KEV added this week'
            WHEN has_exploit_ref = TRUE AND cvss_score >= 9.0
                THEN 'public exploit reference + CVSS >= 9'
            WHEN cvss_severity = 'CRITICAL'
                 AND confidentiality_impact = 'HIGH'
                THEN 'CRITICAL severity with HIGH confidentiality impact'
            ELSE 'modified in window'
        END AS tier_reason
    FROM window_rows
)
SELECT
    cve_id,
    tier,
    tier_reason,
    description_en,
    vuln_status,
    published_date,
    last_modified,
    cvss_version,
    cvss_score,
    cvss_severity,
    exploitability_score,
    impact_score,
    confidentiality_impact,
    integrity_impact,
    has_exploit_ref,
    is_kev,
    kev_date_added,
    kev_ransomware_use,
    kev_required_action,
    kev_due_date,
    kev_vendor_project,
    kev_product
FROM tiered
WHERE tier <= %(max_tier)s
ORDER BY
    tier ASC,
    kev_date_added DESC NULLS LAST,
    cvss_score DESC NULLS LAST,
    exploitability_score DESC NULLS LAST,
    impact_score DESC NULLS LAST,
    last_modified DESC NULLS LAST
LIMIT %(limit)s
"""

# "This week's newly exploited" feed — a dedicated query that can't be
# starved by Tier 1's long tail of re-analyzed evergreen KEV CVEs. The
# orchestrator surfaces this as its own section in the brief ("This week's
# newly added KEV"), separate from the top-N danger list.
_NEWLY_ADDED_KEV_SQL = """
SELECT
    cve_id,
    2 AS tier,
    'KEV added this week' AS tier_reason,
    description_en,
    vuln_status,
    published_date,
    last_modified,
    cvss_version,
    cvss_score,
    cvss_severity,
    exploitability_score,
    impact_score,
    confidentiality_impact,
    integrity_impact,
    has_exploit_ref,
    is_kev,
    kev_date_added,
    kev_ransomware_use,
    kev_required_action,
    kev_due_date,
    kev_vendor_project,
    kev_product
FROM cve_records
WHERE vuln_status <> 'REJECTED'
  AND is_kev = TRUE
  AND kev_date_added >= %(start_date)s
  AND kev_date_added < %(end_date)s
ORDER BY
    kev_date_added DESC NULLS LAST,
    -- Within the same added-date, promote ransomware-linked entries.
    CASE WHEN kev_ransomware_use = 'Known' THEN 0 ELSE 1 END ASC,
    cvss_score DESC NULLS LAST,
    exploitability_score DESC NULLS LAST,
    impact_score DESC NULLS LAST
LIMIT %(limit)s
"""

_SUMMARY_SQL = """
SELECT
    COUNT(*) AS total_modified,
    COUNT_IF(published_date >= %(start_date)s
             AND published_date < %(end_date)s) AS newly_published,
    COUNT_IF(cvss_severity = 'CRITICAL') AS critical_count,
    COUNT_IF(is_kev = TRUE
             AND kev_date_added >= %(start_date)s
             AND kev_date_added < %(end_date)s) AS kev_added_count,
    COUNT_IF(is_kev = TRUE AND kev_ransomware_use = 'Known')
        AS kev_ransomware_count,
    COUNT_IF(has_exploit_ref = TRUE) AS has_exploit_ref_count
FROM cve_records
WHERE vuln_status <> 'REJECTED'
  AND (
      (last_modified >= %(start_ts)s AND last_modified < %(end_ts)s)
      OR (is_kev = TRUE
          AND kev_date_added >= %(start_date)s
          AND kev_date_added < %(end_date)s)
  )
"""


# -- helpers ----------------------------------------------------------------


def _resolve_window(
    window_start: date | None,
    window_end: date | None,
    default_days: int = DEFAULT_WINDOW_DAYS,
) -> tuple[date, date]:
    """Resolve the [start, end) window with sane defaults.

    Defaults to the past ``default_days`` ending today (exclusive). If only
    one end is given, the other is derived.
    """
    if window_end is None:
        window_end = date.today()
    if window_start is None:
        window_start = window_end - timedelta(days=default_days)
    if window_start >= window_end:
        raise ValueError(
            f"window_start ({window_start}) must be before window_end ({window_end})"
        )
    return window_start, window_end


def _params(window_start: date, window_end: date, **extra) -> dict:
    """Build the param dict used by both SQL queries.

    ``last_modified`` is TIMESTAMP_NTZ so we pass naive datetimes; KEV /
    published dates are DATE so we pass ``date`` objects. Snowflake's
    pyformat paramstyle handles both.
    """
    return {
        "start_date": window_start,
        "end_date": window_end,
        "start_ts": datetime.combine(window_start, datetime.min.time()),
        "end_ts": datetime.combine(window_end, datetime.min.time()),
        **extra,
    }


# -- public API -------------------------------------------------------------


def top_cves(
    *,
    window_start: date | None = None,
    window_end: date | None = None,
    limit: int = DEFAULT_TOP_N,
    max_tier: int = DEFAULT_MAX_TIER,
) -> list[WeeklyCve]:
    """Return tier-ranked CVEs modified (or KEV-added) within the window.

    Default behaviour matches the weekly brief: past 7 days, tier 1-4 only,
    top 10 rows. Pass ``max_tier=5`` to include the low-signal tail.
    """
    start_d, end_d = _resolve_window(window_start, window_end)
    params = _params(start_d, end_d, limit=int(limit), max_tier=int(max_tier))

    sf = get_snowflake_service()
    rows = sf.execute_query(_TOP_CVES_SQL, params)

    log.info(
        "weekly_digest_top_cves",
        window_start=start_d.isoformat(),
        window_end=end_d.isoformat(),
        limit=limit,
        max_tier=max_tier,
        n=len(rows),
    )
    return [WeeklyCve.model_validate(r) for r in rows]


def summary_counts(
    *,
    window_start: date | None = None,
    window_end: date | None = None,
) -> WeeklyDigestSummary:
    """Return the headline counts for the week — goes above the top-N list."""
    start_d, end_d = _resolve_window(window_start, window_end)
    params = _params(start_d, end_d)

    sf = get_snowflake_service()
    row = sf.execute_one(_SUMMARY_SQL, params) or {}

    summary = WeeklyDigestSummary(
        window_start=start_d,
        window_end=end_d,
        total_modified=int(row.get("total_modified") or 0),
        newly_published=int(row.get("newly_published") or 0),
        critical_count=int(row.get("critical_count") or 0),
        kev_added_count=int(row.get("kev_added_count") or 0),
        kev_ransomware_count=int(row.get("kev_ransomware_count") or 0),
        has_exploit_ref_count=int(row.get("has_exploit_ref_count") or 0),
    )
    log.info("weekly_digest_summary", **summary.model_dump(mode="json"))
    return summary


def newly_added_kev(
    *,
    window_start: date | None = None,
    window_end: date | None = None,
    limit: int = DEFAULT_NEWLY_ADDED_KEV_N,
) -> list[WeeklyCve]:
    """CVEs added to the CISA KEV catalog within the window.

    Separate from ``top_cves`` so the brief can dedicate a "This week's newly
    exploited" section without competing for slots against Tier 1's long tail
    of evergreen KEV + ransomware entries (which dominate purely by CVSS).

    Rows are ordered by:

    1. ``kev_date_added DESC`` — newest addition first.
    2. Ransomware-linked entries (``kev_ransomware_use = 'Known'``) before
       non-ransomware within the same added-date.
    3. ``cvss_score / exploitability_score / impact_score`` as final
       tiebreakers.

    All rows come back with ``tier = 2`` and
    ``tier_reason = 'KEV added this week'`` for display consistency.
    """
    start_d, end_d = _resolve_window(window_start, window_end)
    params = _params(start_d, end_d, limit=int(limit))

    sf = get_snowflake_service()
    rows = sf.execute_query(_NEWLY_ADDED_KEV_SQL, params)

    log.info(
        "weekly_digest_newly_added_kev",
        window_start=start_d.isoformat(),
        window_end=end_d.isoformat(),
        limit=limit,
        n=len(rows),
    )
    return [WeeklyCve.model_validate(r) for r in rows]


def weekly_digest(
    *,
    window_start: date | None = None,
    window_end: date | None = None,
    limit: int = DEFAULT_TOP_N,
    max_tier: int = DEFAULT_MAX_TIER,
    newly_added_limit: int = DEFAULT_NEWLY_ADDED_KEV_N,
) -> dict:
    """One-shot convenience: summary + top CVEs + newly-added KEV in one dict.

    Shape matches what the brief orchestrator consumes:

    .. code-block:: python

        {
            "summary": WeeklyDigestSummary,
            "top_cves": list[WeeklyCve],          # tier-ranked danger list
            "newly_added_kev": list[WeeklyCve],   # "this week's news" feed
        }

    ``newly_added_kev`` is queried independently of ``top_cves`` — Tier 1's
    evergreen KEV entries cannot starve the newly-added list even if they
    fill every slot in ``top_cves``.
    """
    start_d, end_d = _resolve_window(window_start, window_end)
    summary = summary_counts(window_start=start_d, window_end=end_d)
    top = top_cves(
        window_start=start_d,
        window_end=end_d,
        limit=limit,
        max_tier=max_tier,
    )
    newly = newly_added_kev(
        window_start=start_d,
        window_end=end_d,
        limit=newly_added_limit,
    )
    return {"summary": summary, "top_cves": top, "newly_added_kev": newly}
