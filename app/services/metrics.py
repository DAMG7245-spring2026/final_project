"""Dashboard metrics service for the Home operational overview."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from app.services.snowflake import get_snowflake_service

log = structlog.get_logger(__name__)


def _count_or_zero(sql: str) -> int:
    """Return COUNT(*) result; degrade to 0 if table is unavailable."""
    sf = get_snowflake_service()
    try:
        row = sf.execute_one(sql) or {}
        return int(row.get("n") or 0)
    except Exception as exc:
        log.warning("metrics_count_query_failed", query=sql, error=str(exc))
        return 0


def overview_counts() -> dict[str, int]:
    """Top-card counts for Home dashboard."""
    return {
        "total_cves_ingested": _count_or_zero("SELECT COUNT(*) AS n FROM cve_records"),
        "kev_flagged": _count_or_zero(
            "SELECT COUNT(*) AS n FROM cve_records WHERE is_kev = TRUE"
        ),
        "attack_techniques_loaded": _count_or_zero(
            "SELECT COUNT(*) AS n FROM attack_techniques"
        ),
        "advisories_indexed": _count_or_zero("SELECT COUNT(*) AS n FROM advisories"),
    }


def severity_distribution() -> list[dict[str, Any]]:
    """CRITICAL/HIGH/MEDIUM/LOW distribution from cve_records."""
    sql = """
        SELECT
            COALESCE(cvss_severity, 'UNKNOWN') AS severity,
            COUNT(*) AS count
        FROM cve_records
        WHERE vuln_status <> 'REJECTED'
        GROUP BY 1
    """
    sf = get_snowflake_service()
    rows = sf.execute_query(sql)
    rank = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}
    normalized = [
        {"severity": str(r.get("severity") or "UNKNOWN").upper(), "count": int(r.get("count") or 0)}
        for r in rows
    ]
    normalized.sort(key=lambda r: (rank.get(r["severity"], 99), r["severity"]))
    return normalized


def top_kev_cves(limit: int = 5) -> list[dict[str, Any]]:
    """Most recently added KEV CVEs for the dashboard table."""
    sql = """
        SELECT
            cve_id,
            kev_vendor_project AS vendor,
            kev_product AS product,
            kev_due_date AS due_date,
            kev_date_added AS date_added
        FROM cve_records
        WHERE is_kev = TRUE
        ORDER BY kev_date_added DESC NULLS LAST
        LIMIT %s
    """
    sf = get_snowflake_service()
    rows = sf.execute_query(sql, (int(limit),))
    return [
        {
            "cve_id": r.get("cve_id"),
            "vendor": r.get("vendor"),
            "product": r.get("product"),
            "due_date": r.get("due_date"),
            "date_added": r.get("date_added"),
        }
        for r in rows
    ]


def recent_pipeline_runs(limit: int = 10) -> list[dict[str, Any]]:
    """Last N pipeline runs, newest first."""
    sql = """
        SELECT
            dag_id,
            source,
            status,
            records_fetched,
            started_at,
            completed_at,
            DATEDIFF('second', started_at, completed_at) AS duration_seconds
        FROM pipeline_runs
        ORDER BY completed_at DESC NULLS LAST, started_at DESC NULLS LAST
        LIMIT %s
    """
    sf = get_snowflake_service()
    rows = sf.execute_query(sql, (int(limit),))
    shaped: list[dict[str, Any]] = []
    for r in rows:
        shaped.append(
            {
                "dag": r.get("dag_id"),
                "source": r.get("source"),
                "status": r.get("status"),
                "rows_processed": int(r.get("records_fetched") or 0),
                "duration_seconds": int(r.get("duration_seconds") or 0),
                "timestamp": r.get("completed_at") or r.get("started_at"),
            }
        )
    return shaped


def freshness_by_source() -> dict[str, datetime | None]:
    """Last completed timestamp for key ingestion sources."""
    sql = """
        SELECT source, MAX(completed_at) AS last_completed_at
        FROM pipeline_runs
        GROUP BY source
    """
    sf = get_snowflake_service()
    rows = sf.execute_query(sql)
    by_source = {
        str(r.get("source") or "").lower(): r.get("last_completed_at")
        for r in rows
    }
    return {
        "nvd": by_source.get("nvd"),
        "kev": by_source.get("kev"),
        "attck": by_source.get("attck") or by_source.get("mitre_attck"),
        "neo4j": by_source.get("neo4j"),
    }
