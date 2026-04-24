"""Task 2: drain kev_pending_fetch via NVD single-CVE ingest, then apply KEV columns."""

from __future__ import annotations

import logging
from time import perf_counter
from typing import Any

from ingestion.nvd.pipeline import sync_single_cve

logger = logging.getLogger(__name__)


def _apply_kev_from_pending(cve_id: str, row: dict[str, Any]) -> None:
    from app.services.snowflake import get_snowflake_service

    sf = get_snowflake_service()
    sf.execute_write(
        """
        UPDATE cve_records
        SET
            is_kev = TRUE,
            kev_date_added = %s,
            kev_ransomware_use = %s,
            kev_required_action = %s,
            kev_due_date = %s,
            kev_vendor_project = %s,
            kev_product = %s,
            kev_neo4j_dirty = TRUE
        WHERE cve_id = %s
        """,
        (
            row.get("kev_date_added"),
            row.get("kev_ransomware_use"),
            row.get("kev_required_action"),
            row.get("kev_due_date"),
            row.get("kev_vendor_project"),
            row.get("kev_product"),
            cve_id,
        ),
    )


def _mark_pending_fetched(cve_id: str) -> None:
    from app.services.snowflake import get_snowflake_service

    get_snowflake_service().execute_write(
        "UPDATE kev_pending_fetch SET fetched = TRUE WHERE cve_id = %s",
        (cve_id,),
    )


def run_resolve_kev_pending(
    *,
    batch_size: int = 50,
    max_batches: int | None = None,
) -> dict[str, Any]:
    """
    For each row in ``kev_pending_fetch`` with ``fetched = FALSE``, upsert CVE via NVD,
    overlay KEV fields from the pending row, mark ``kev_neo4j_dirty``, then ``fetched = TRUE``.
    """
    from app.services.snowflake import get_snowflake_service

    sf = get_snowflake_service()
    t0 = perf_counter()
    processed = 0
    batches = 0
    errors: list[str] = []

    while True:
        if max_batches is not None and batches >= max_batches:
            break
        rows = sf.execute_query(
            """
            SELECT
                cve_id,
                kev_date_added,
                kev_ransomware_use,
                kev_required_action,
                kev_due_date,
                kev_vendor_project,
                kev_product
            FROM kev_pending_fetch
            WHERE COALESCE(fetched, FALSE) = FALSE
            ORDER BY cve_id
            LIMIT %s
            """,
            (batch_size,),
        )
        if not rows:
            break
        batches += 1
        for row in rows:
            cve_id = str(row["cve_id"]).strip().upper()
            try:
                sync_single_cve(cve_id)
                _apply_kev_from_pending(cve_id, row)
                _mark_pending_fetched(cve_id)
                processed += 1
            except Exception as exc:
                logger.exception("resolve_kev_pending failed for %s", cve_id)
                errors.append(f"{cve_id}: {exc}")
                # leave fetched=FALSE for retry
        if len(rows) < batch_size:
            break

    elapsed = perf_counter() - t0
    return {
        "processed": processed,
        "batches": batches,
        "elapsed_sec": elapsed,
        "errors": errors[:50],
        "error_count": len(errors),
    }
