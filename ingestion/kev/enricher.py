"""High-throughput KEV enrichment into Snowflake."""

from __future__ import annotations

import json
import logging
import tempfile
from datetime import date, datetime, timezone
from os import unlink
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

from ingestion.kev.client import fetch_kev_catalog

logger = logging.getLogger(__name__)

_STAGING_TABLE = "kev_enrichment_staging"
_STAGING_STAGE = "kev_enrichment_stage"

_COLUMNS = [
    "cve_id",
    "kev_date_added",
    "kev_ransomware_use",
    "kev_required_action",
    "kev_due_date",
    "kev_vendor_project",
    "kev_product",
]

CREATE_STAGING_SQL = f"""
CREATE TEMP TABLE IF NOT EXISTS {_STAGING_TABLE} (
    cve_id VARCHAR,
    kev_date_added DATE,
    kev_ransomware_use VARCHAR,
    kev_required_action VARCHAR,
    kev_due_date DATE,
    kev_vendor_project VARCHAR,
    kev_product VARCHAR
)
"""
CREATE_STAGE_SQL = f"CREATE TEMP STAGE IF NOT EXISTS {_STAGING_STAGE}"
TRUNCATE_STAGING_SQL = f"TRUNCATE TABLE {_STAGING_TABLE}"

COPY_INTO_STAGING_SQL_TMPL = f"""
COPY INTO {_STAGING_TABLE} (
    cve_id,
    kev_date_added,
    kev_ransomware_use,
    kev_required_action,
    kev_due_date,
    kev_vendor_project,
    kev_product
)
FROM (
    SELECT
        $1:cve_id::VARCHAR,
        $1:kev_date_added::DATE,
        $1:kev_ransomware_use::VARCHAR,
        $1:kev_required_action::VARCHAR,
        $1:kev_due_date::DATE,
        $1:kev_vendor_project::VARCHAR,
        $1:kev_product::VARCHAR
    FROM { "{stage_path}" }
)
FILE_FORMAT = (TYPE = JSON STRIP_OUTER_ARRAY = FALSE)
PURGE = TRUE
"""

MERGE_EXISTING_SQL = f"""
MERGE INTO cve_records AS t
USING {_STAGING_TABLE} AS s
ON t.cve_id = s.cve_id
WHEN MATCHED THEN UPDATE SET
    t.is_kev = TRUE,
    t.kev_date_added = s.kev_date_added,
    t.kev_ransomware_use = s.kev_ransomware_use,
    t.kev_required_action = s.kev_required_action,
    t.kev_due_date = s.kev_due_date,
    t.kev_vendor_project = s.kev_vendor_project,
    t.kev_product = s.kev_product
"""

MERGE_QUEUE_SQL = f"""
MERGE INTO kev_pending_fetch AS q
USING (
    SELECT s.cve_id, s.kev_date_added
    FROM {_STAGING_TABLE} AS s
    LEFT JOIN cve_records AS c
      ON c.cve_id = s.cve_id
    WHERE c.cve_id IS NULL
) AS m
ON q.cve_id = m.cve_id
WHEN MATCHED THEN UPDATE SET
    q.kev_date_added = COALESCE(m.kev_date_added, q.kev_date_added),
    q.fetched = FALSE
WHEN NOT MATCHED THEN INSERT (cve_id, kev_date_added, fetched)
VALUES (m.cve_id, m.kev_date_added, FALSE)
"""

FALLBACK_INSERT_SQL = f"""
INSERT INTO {_STAGING_TABLE} (
    cve_id, kev_date_added, kev_ransomware_use, kev_required_action,
    kev_due_date, kev_vendor_project, kev_product
) VALUES (%s, %s, %s, %s, %s, %s, %s)
"""


def _get_snowflake_service():
    from app.services.snowflake import get_snowflake_service

    return get_snowflake_service()


def _parse_date(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        return date.fromisoformat(raw).isoformat()
    except ValueError:
        return None


def _clip(raw: Any, max_len: int) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    return text[:max_len]


def _to_stage_row(entry: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = str(entry.get("cveID") or "").strip().upper()
    if not cve_id:
        return None
    return {
        "cve_id": cve_id,
        "kev_date_added": _parse_date(entry.get("dateAdded")),
        "kev_ransomware_use": _clip(entry.get("knownRansomwareCampaignUse"), 50),
        "kev_required_action": (entry.get("requiredAction") or "").strip() or None,
        "kev_due_date": _parse_date(entry.get("dueDate")),
        "kev_vendor_project": _clip(entry.get("vendorProject"), 100),
        "kev_product": _clip(entry.get("product"), 100),
    }


def _dedupe_rows(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_cve: dict[str, dict[str, Any]] = {}
    for entry in entries:
        row = _to_stage_row(entry)
        if row is not None:
            by_cve[row["cve_id"]] = row
    return list(by_cve.values())


def _write_jsonl(rows: list[dict[str, Any]]) -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        for row in rows:
            payload = {col: row.get(col) for col in _COLUMNS}
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return Path(f.name)


def _bulk_path(cur: Any, rows: list[dict[str, Any]]) -> None:
    batch_file = _write_jsonl(rows)
    stage_file = f"batch_{uuid4().hex}.jsonl"
    put_path = str(batch_file.resolve()).replace("\\", "\\\\")
    put_sql = (
        f"PUT 'file://{put_path}' @{_STAGING_STAGE}/{stage_file} "
        "AUTO_COMPRESS=FALSE OVERWRITE=TRUE"
    )
    copy_sql = COPY_INTO_STAGING_SQL_TMPL.format(stage_path=f"@{_STAGING_STAGE}/{stage_file}")
    try:
        cur.execute(CREATE_STAGING_SQL)
        cur.execute(CREATE_STAGE_SQL)
        cur.execute(TRUNCATE_STAGING_SQL)
        cur.execute(put_sql)
        cur.execute(copy_sql)
        cur.execute(MERGE_EXISTING_SQL)
        cur.execute(MERGE_QUEUE_SQL)
    finally:
        try:
            unlink(batch_file)
        except OSError:
            pass


def _fallback_path(cur: Any, rows: list[dict[str, Any]], chunk_size: int = 1000) -> None:
    cur.execute(CREATE_STAGING_SQL)
    cur.execute(TRUNCATE_STAGING_SQL)
    for i in range(0, len(rows), chunk_size):
        chunk = rows[i : i + chunk_size]
        params = [
            (
                r["cve_id"],
                r.get("kev_date_added"),
                r.get("kev_ransomware_use"),
                r.get("kev_required_action"),
                r.get("kev_due_date"),
                r.get("kev_vendor_project"),
                r.get("kev_product"),
            )
            for r in chunk
        ]
        cur.executemany(FALLBACK_INSERT_SQL, params)
    cur.execute(MERGE_EXISTING_SQL)
    cur.execute(MERGE_QUEUE_SQL)


def _count_joined(cur: Any, rows: list[dict[str, Any]]) -> tuple[int, int]:
    if not rows:
        return (0, 0)
    value_rows_parts: list[str] = []
    for row in rows:
        cve_id = str(row["cve_id"]).replace("'", "''")
        value_rows_parts.append(f"('{cve_id}')")
    value_rows = ",".join(value_rows_parts)
    cur.execute(
        f"""
        SELECT
          COUNT_IF(c.cve_id IS NOT NULL) AS existing_count,
          COUNT_IF(c.cve_id IS NULL) AS missing_count
        FROM (
          SELECT column1 AS cve_id
          FROM VALUES {value_rows}
        ) v
        LEFT JOIN cve_records c ON c.cve_id = v.cve_id
        """
    )
    result = cur.fetchone() or (0, 0)
    return int(result[0] or 0), int(result[1] or 0)


def run_kev_sync(feed_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Fetch KEV catalog and enrich Snowflake with bulk-first strategy."""
    run_id = uuid4().hex[:12]
    started = perf_counter()
    mode = "bulk"
    timings: dict[str, float] = {}

    t0 = perf_counter()
    entries = feed_rows if feed_rows is not None else fetch_kev_catalog()
    timings["fetch"] = perf_counter() - t0

    t1 = perf_counter()
    rows = _dedupe_rows(entries)
    timings["prepare"] = perf_counter() - t1
    if not rows:
        elapsed = perf_counter() - started
        logger.info(
            "kev_sync_summary run_id=%s mode=%s feed_size=%s deduped_rows=0 existing_count=0 missing_count=0 elapsed_sec=%.3f",
            run_id,
            mode,
            len(entries),
            elapsed,
        )
        return {
            "run_id": run_id,
            "mode": mode,
            "feed_size": len(entries),
            "deduped_rows": 0,
            "existing_count": 0,
            "missing_count": 0,
            "elapsed_sec": elapsed,
            "timings_sec": timings,
        }

    sf = _get_snowflake_service()
    with sf.cursor() as cur:
        try:
            t_stage = perf_counter()
            _bulk_path(cur, rows)
            timings["stage_copy_merge_queue"] = perf_counter() - t_stage
        except Exception as exc:
            mode = "fallback"
            logger.warning(
                "kev_sync_fallback run_id=%s reason=%s mode=%s",
                run_id,
                getattr(exc, "errno", None) or exc.__class__.__name__,
                mode,
            )
            t_fb = perf_counter()
            _fallback_path(cur, rows)
            timings["fallback_merge_queue"] = perf_counter() - t_fb
        t_count = perf_counter()
        existing_count, missing_count = _count_joined(cur, rows)
        timings["count"] = perf_counter() - t_count

    elapsed = perf_counter() - started
    logger.info(
        "kev_sync_timings run_id=%s fetch=%.3f prepare=%.3f count=%.3f mode=%s",
        run_id,
        timings.get("fetch", 0.0),
        timings.get("prepare", 0.0),
        timings.get("count", 0.0),
        mode,
    )
    logger.info(
        "kev_sync_summary run_id=%s mode=%s feed_size=%s deduped_rows=%s existing_count=%s missing_count=%s elapsed_sec=%.3f",
        run_id,
        mode,
        len(entries),
        len(rows),
        existing_count,
        missing_count,
        elapsed,
    )
    return {
        "run_id": run_id,
        "mode": mode,
        "feed_size": len(entries),
        "deduped_rows": len(rows),
        "existing_count": existing_count,
        "missing_count": missing_count,
        "elapsed_sec": elapsed,
        "timings_sec": timings,
    }

