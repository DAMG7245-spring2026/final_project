"""Sync CVE, CWE, and HAS_WEAKNESS edges from Snowflake into Neo4j (option A)."""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import Any, Callable

from app.config import get_settings
from app.services import get_neo4j_service, get_snowflake_service
from app.services.neo4j_service import _session_kwargs

logger = logging.getLogger(__name__)

_MAX_DESC = 28000

_ENSURE_CONSTRAINTS_CVE = """
CREATE CONSTRAINT cve_id_unique IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE
"""

_ENSURE_CONSTRAINTS_CWE = """
CREATE CONSTRAINT cwe_id_unique IF NOT EXISTS FOR (n:CWE) REQUIRE n.id IS UNIQUE
"""

_MERGE_CWE_BATCH = """
UNWIND $rows AS row
MERGE (w:CWE {id: row.id})
SET w.name = row.name,
    w.abstraction = row.abstraction,
    w.status = row.status,
    w.is_deprecated = row.is_deprecated
"""

_MERGE_CVE_BATCH = """
UNWIND $rows AS row
MERGE (c:CVE {id: row.id})
SET c.published_date = row.published_date,
    c.last_modified = row.last_modified,
    c.vuln_status = row.vuln_status,
    c.description_en = row.description_en,
    c.cvss_version = row.cvss_version,
    c.cvss_score = row.cvss_score,
    c.cvss_severity = row.cvss_severity,
    c.attack_vector = row.attack_vector,
    c.attack_complexity = row.attack_complexity,
    c.privileges_required = row.privileges_required,
    c.user_interaction = row.user_interaction,
    c.scope = row.scope,
    c.confidentiality_impact = row.confidentiality_impact,
    c.integrity_impact = row.integrity_impact,
    c.has_exploit_ref = row.has_exploit_ref,
    c.is_kev = row.is_kev,
    c.kev_date_added = row.kev_date_added,
    c.kev_ransomware_use = row.kev_ransomware_use,
    c.kev_required_action = row.kev_required_action,
    c.kev_due_date = row.kev_due_date,
    c.kev_vendor_project = row.kev_vendor_project,
    c.kev_product = row.kev_product
"""

_MERGE_RELS_BATCH = """
UNWIND $rows AS row
MATCH (c:CVE {id: row.cve_id})
MATCH (w:CWE {id: row.cwe_id})
MERGE (c)-[r:HAS_WEAKNESS]->(w)
SET r.mapping_source = row.mapping_source,
    r.mapping_type = row.mapping_type
"""


def _iso(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (date, datetime)):
        return v.isoformat()
    return v


def _trunc(s: Any, max_len: int = _MAX_DESC) -> str | None:
    if s is None:
        return None
    text = str(s)
    if len(text) <= max_len:
        return text
    return text[:max_len]


def _resolved_neo4j_database(override: str | None) -> str | None:
    if override is not None and override.strip():
        return override.strip()
    return (get_settings().neo4j_database or "").strip() or None


def _neo4j_write_transaction(
    work: Callable[[Any], None],
    database: str | None = None,
) -> None:
    neo = get_neo4j_service()
    driver = neo.connect()
    with driver.session(**_session_kwargs(database)) as session:
        session.execute_write(work)


def _ensure_constraints(database: str | None = None) -> None:
    def work(tx: Any) -> None:
        tx.run(_ENSURE_CONSTRAINTS_CVE)
        tx.run(_ENSURE_CONSTRAINTS_CWE)

    _neo4j_write_transaction(work, database=database)


def _fetch_cve_id_batch(batch_size: int, *, full: bool, offset: int) -> list[str]:
    sf = get_snowflake_service()
    if full:
        sql = """
        SELECT cve_id
        FROM cve_records
        ORDER BY cve_id
        LIMIT %s OFFSET %s
        """
        rows = sf.execute_query(sql, (batch_size, offset))
    else:
        sql = """
        SELECT cve_id
        FROM cve_records
        WHERE COALESCE(loaded_to_neo4j, FALSE) = FALSE
        ORDER BY cve_id
        LIMIT %s
        """
        rows = sf.execute_query(sql, (batch_size,))
    return [str(r["cve_id"]) for r in rows if r.get("cve_id")]


def _fetch_cve_rows(cve_ids: list[str]) -> list[dict[str, Any]]:
    if not cve_ids:
        return []
    sf = get_snowflake_service()
    ph = ",".join(["%s"] * len(cve_ids))
    sql = f"""
    SELECT
        cve_id,
        published_date,
        last_modified,
        vuln_status,
        description_en,
        cvss_version,
        cvss_score,
        cvss_severity,
        attack_vector,
        attack_complexity,
        privileges_required,
        user_interaction,
        scope,
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
    WHERE cve_id IN ({ph})
    """
    return sf.execute_query(sql, tuple(cve_ids))


def _fetch_mappings_for_cves(cve_ids: list[str]) -> list[dict[str, Any]]:
    if not cve_ids:
        return []
    sf = get_snowflake_service()
    ph = ",".join(["%s"] * len(cve_ids))
    sql = f"""
    SELECT mapping_id, cve_id, cwe_id, mapping_source, mapping_type
    FROM cve_cwe_mappings
    WHERE cve_id IN ({ph})
      AND cwe_id IS NOT NULL
    """
    return sf.execute_query(sql, tuple(cve_ids))


def _fetch_cwe_rows(cwe_ids: list[str]) -> list[dict[str, Any]]:
    if not cwe_ids:
        return []
    sf = get_snowflake_service()
    ph = ",".join(["%s"] * len(cwe_ids))
    sql = f"""
    SELECT cwe_id, name, abstraction, status, is_deprecated
    FROM cwe_records
    WHERE cwe_id IN ({ph})
    """
    found = sf.execute_query(sql, tuple(cwe_ids))
    found_ids = {str(r["cwe_id"]) for r in found}
    for cid in cwe_ids:
        if cid not in found_ids:
            found.append(
                {
                    "cwe_id": cid,
                    "name": None,
                    "abstraction": None,
                    "status": None,
                    "is_deprecated": False,
                }
            )
    return found


def _cve_to_neo_row(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(r["cve_id"]),
        "published_date": _iso(r.get("published_date")),
        "last_modified": _iso(r.get("last_modified")),
        "vuln_status": r.get("vuln_status"),
        "description_en": _trunc(r.get("description_en")),
        "cvss_version": r.get("cvss_version"),
        "cvss_score": r.get("cvss_score"),
        "cvss_severity": r.get("cvss_severity"),
        "attack_vector": r.get("attack_vector"),
        "attack_complexity": r.get("attack_complexity"),
        "privileges_required": r.get("privileges_required"),
        "user_interaction": r.get("user_interaction"),
        "scope": r.get("scope"),
        "confidentiality_impact": r.get("confidentiality_impact"),
        "integrity_impact": r.get("integrity_impact"),
        "has_exploit_ref": bool(r.get("has_exploit_ref")),
        "is_kev": bool(r.get("is_kev")),
        "kev_date_added": _iso(r.get("kev_date_added")),
        "kev_ransomware_use": r.get("kev_ransomware_use"),
        "kev_required_action": r.get("kev_required_action"),
        "kev_due_date": _iso(r.get("kev_due_date")),
        "kev_vendor_project": r.get("kev_vendor_project"),
        "kev_product": r.get("kev_product"),
    }


def _cwe_to_neo_row(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(r["cwe_id"]),
        "name": r.get("name"),
        "abstraction": r.get("abstraction"),
        "status": r.get("status"),
        "is_deprecated": bool(r.get("is_deprecated")),
    }


def _rel_to_neo_row(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": str(r["cve_id"]),
        "cwe_id": str(r["cwe_id"]),
        "mapping_source": r.get("mapping_source") or "nvd",
        "mapping_type": r.get("mapping_type") or "PrimaryOrSecondary",
    }


def _mark_snowflake_synced(
    cve_ids: list[str],
    mapping_ids: list[str],
    cwe_ids: list[str],
) -> None:
    if not cve_ids and not mapping_ids and not cwe_ids:
        return
    sf = get_snowflake_service()
    with sf.cursor() as cur:
        if cve_ids:
            ph = ",".join(["%s"] * len(cve_ids))
            cur.execute(
                f"""
                UPDATE cve_records
                SET loaded_to_neo4j = TRUE,
                    neo4j_loaded_at = CURRENT_TIMESTAMP()
                WHERE cve_id IN ({ph})
                """,
                tuple(cve_ids),
            )
        if mapping_ids:
            ph = ",".join(["%s"] * len(mapping_ids))
            cur.execute(
                f"""
                UPDATE cve_cwe_mappings
                SET loaded_to_neo4j = TRUE
                WHERE mapping_id IN ({ph})
                """,
                tuple(mapping_ids),
            )
        if cwe_ids:
            ph = ",".join(["%s"] * len(cwe_ids))
            cur.execute(
                f"""
                UPDATE cwe_records
                SET loaded_to_neo4j = TRUE
                WHERE cwe_id IN ({ph})
                """,
                tuple(cwe_ids),
            )


def _write_batch_to_neo4j(
    cwe_rows: list[dict[str, Any]],
    cve_rows: list[dict[str, Any]],
    rel_rows: list[dict[str, Any]],
    database: str | None,
) -> None:
    cwe_neo = [_cwe_to_neo_row(r) for r in cwe_rows]
    cve_neo = [_cve_to_neo_row(r) for r in cve_rows]
    rel_neo = [_rel_to_neo_row(r) for r in rel_rows]

    def work(tx: Any) -> None:
        if cwe_neo:
            tx.run(_MERGE_CWE_BATCH, rows=cwe_neo)
        if cve_neo:
            tx.run(_MERGE_CVE_BATCH, rows=cve_neo)
        if rel_neo:
            tx.run(_MERGE_RELS_BATCH, rows=rel_neo)

    _neo4j_write_transaction(work, database=database)


def run_cve_cwe_kev_sync(
    *,
    batch_size: int = 200,
    full: bool = False,
    neo4j_database: str | None = None,
    max_batches: int | None = None,
) -> dict[str, Any]:
    """
    For each batch of CVE ids, upsert CWE nodes, CVE nodes (including KEV fields),
    HAS_WEAKNESS edges from ``cve_cwe_mappings``, then mark Snowflake rows synced.

    Incremental (default): only ``cve_records`` with ``loaded_to_neo4j = FALSE``.

    Full scan: paginate all CVEs with LIMIT/OFFSET (re-upserts graph; still updates
    Snowflake flags).
    """
    if batch_size < 1:
        batch_size = 1
    db = _resolved_neo4j_database(neo4j_database)
    _ensure_constraints(db)

    total_cve = 0
    total_cwe = 0
    total_rel = 0
    batches = 0
    offset = 0

    while True:
        if max_batches is not None and batches >= max_batches:
            break
        cve_ids = _fetch_cve_id_batch(batch_size, full=full, offset=offset)
        if not cve_ids:
            break
        cve_rows = _fetch_cve_rows(cve_ids)
        mappings = _fetch_mappings_for_cves(cve_ids)
        cwe_ids = sorted({str(m["cwe_id"]) for m in mappings if m.get("cwe_id")})
        cwe_rows = _fetch_cwe_rows(cwe_ids) if cwe_ids else []

        mapping_ids = [str(m["mapping_id"]) for m in mappings if m.get("mapping_id")]

        try:
            _write_batch_to_neo4j(cwe_rows, cve_rows, mappings, db)
        except Exception:
            logger.exception("Neo4j sync failed for batch starting %s", cve_ids[0])
            raise

        _mark_snowflake_synced(
            [str(r["cve_id"]) for r in cve_rows],
            mapping_ids,
            cwe_ids,
        )

        total_cve += len(cve_rows)
        total_cwe += len(cwe_rows)
        total_rel += len(mappings)
        batches += 1
        if full:
            offset += len(cve_ids)
        logger.info(
            "graph_sync batch=%s cves=%s cwes=%s rels=%s full=%s",
            batches,
            len(cve_rows),
            len(cwe_rows),
            len(mappings),
            full,
        )

    return {
        "batches": batches,
        "cves_processed": total_cve,
        "cwes_touched": total_cwe,
        "relationships_merged": total_rel,
        "full_scan": full,
        "neo4j_database": db or "default",
    }
