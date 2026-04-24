"""Task 3: push KEV-related CVE properties to Neo4j for rows marked kev_neo4j_dirty."""

from __future__ import annotations

import logging
from time import perf_counter
from typing import Any

from app.config import get_settings
from app.services import get_snowflake_service
from app.services.neo4j_service import _session_kwargs

from ingestion.graph_sync.cve_cwe_kev import _neo4j_write_transaction, _resolved_neo4j_database

logger = logging.getLogger(__name__)

_MERGE_CVE_KEV_PROPS = """
UNWIND $rows AS row
MERGE (c:CVE {id: row.id})
SET c.is_kev = row.is_kev,
    c.kev_date_added = row.kev_date_added,
    c.kev_ransomware_use = row.kev_ransomware_use,
    c.kev_required_action = row.kev_required_action,
    c.kev_due_date = row.kev_due_date,
    c.kev_vendor_project = row.kev_vendor_project,
    c.kev_product = row.kev_product
"""


def _row_to_neo(r: dict[str, Any]) -> dict[str, Any]:
    def _iso(v: Any) -> Any:
        if v is None:
            return None
        if hasattr(v, "isoformat"):
            return v.isoformat()
        return v

    return {
        "id": str(r["cve_id"]).strip(),
        "is_kev": bool(r.get("is_kev")),
        "kev_date_added": _iso(r.get("kev_date_added")),
        "kev_ransomware_use": r.get("kev_ransomware_use"),
        "kev_required_action": r.get("kev_required_action"),
        "kev_due_date": _iso(r.get("kev_due_date")),
        "kev_vendor_project": r.get("kev_vendor_project"),
        "kev_product": r.get("kev_product"),
    }


def _clear_dirty(cve_ids: list[str]) -> None:
    if not cve_ids:
        return
    sf = get_snowflake_service()
    ph = ",".join(["%s"] * len(cve_ids))
    sf.execute_write(
        f"""
        UPDATE cve_records
        SET kev_neo4j_dirty = FALSE
        WHERE cve_id IN ({ph})
        """,
        tuple(cve_ids),
    )


def run_sync_kev_neo4j(
    *,
    batch_size: int = 200,
    max_batches: int | None = None,
    neo4j_database: str | None = None,
) -> dict[str, Any]:
    """
    Batch-load CVEs with ``kev_neo4j_dirty = TRUE`` from Snowflake, MERGE KEV props in Neo4j,
    then clear the dirty flag in Snowflake.
    """
    t0 = perf_counter()
    db = _resolved_neo4j_database(neo4j_database)
    sf = get_snowflake_service()
    batches = 0
    total = 0

    while True:
        if max_batches is not None and batches >= max_batches:
            break
        rows = sf.execute_query(
            """
            SELECT
                cve_id,
                is_kev,
                kev_date_added,
                kev_ransomware_use,
                kev_required_action,
                kev_due_date,
                kev_vendor_project,
                kev_product
            FROM cve_records
            WHERE COALESCE(kev_neo4j_dirty, FALSE) = TRUE
            ORDER BY cve_id
            LIMIT %s
            """,
            (batch_size,),
        )
        if not rows:
            break
        neo_rows = [_row_to_neo(r) for r in rows]

        def work(tx: Any) -> None:
            tx.run(_MERGE_CVE_KEV_PROPS, rows=neo_rows)

        _neo4j_write_transaction(work, database=db)
        _clear_dirty([str(r["cve_id"]) for r in rows])
        total += len(rows)
        batches += 1
        logger.info("sync_kev_neo4j batch=%s size=%s", batches, len(rows))
        if len(rows) < batch_size:
            break

    return {
        "batches": batches,
        "cves_updated": total,
        "elapsed_sec": perf_counter() - t0,
        "neo4j_database": db or (get_settings().neo4j_database or ""),
    }
