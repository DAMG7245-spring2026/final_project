"""Option B: MITRE ATT&CK techniques in Neo4j + optional CVE links from advisory chunks."""

from __future__ import annotations

import logging
from typing import Any

from app.services import get_snowflake_service

from ingestion.graph_sync.cve_cwe_kev import (
    _neo4j_write_transaction,
    _resolved_neo4j_database,
    _trunc,
)

logger = logging.getLogger(__name__)

_MAX_DESC = 28000

_ENSURE_TECHNIQUE_CONSTRAINT = """
CREATE CONSTRAINT technique_id_unique IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE
"""

_MERGE_TECHNIQUE_BATCH = """
UNWIND $rows AS row
MERGE (t:Technique {id: row.id})
SET t.name = row.name,
    t.tactic = row.tactic,
    t.description = row.description,
    t.platforms = row.platforms,
    t.is_subtechnique = row.is_subtechnique,
    t.parent_id = row.parent_id,
    t.is_deprecated = row.is_deprecated,
    t.is_revoked = row.is_revoked,
    t.mitre_version = row.mitre_version,
    t.stix_id = row.stix_id
"""

_MERGE_CHUNK_TECHNIQUE_RELS = """
UNWIND $rows AS row
MATCH (c:CVE {id: row.cve_id})
MATCH (t:Technique {id: row.mitre_id})
MERGE (c)-[r:REFERENCES_TECHNIQUE]->(t)
SET r.source = 'advisory_chunk_cooccurrence'
"""


def _technique_to_neo_row(r: dict[str, Any]) -> dict[str, Any]:
    platforms = r.get("platforms")
    if platforms is None:
        pl: list[str] = []
    elif isinstance(platforms, list):
        pl = [str(x) for x in platforms]
    elif isinstance(platforms, str):
        pl = [platforms]
    else:
        pl = list(platforms) if hasattr(platforms, "__iter__") else []

    return {
        "id": str(r["mitre_id"]).strip()[:20],
        "name": r.get("name"),
        "tactic": r.get("tactic"),
        "description": _trunc(r.get("description"), _MAX_DESC),
        "platforms": pl,
        "is_subtechnique": bool(r.get("is_subtechnique")),
        "parent_id": r.get("parent_id"),
        "is_deprecated": bool(r.get("is_deprecated")),
        "is_revoked": bool(r.get("is_revoked")),
        "mitre_version": r.get("mitre_version"),
        "stix_id": r.get("stix_id"),
    }


def _fetch_technique_batch(batch_size: int, *, full: bool, offset: int) -> list[dict[str, Any]]:
    sf = get_snowflake_service()
    if full:
        sql = """
        SELECT
            mitre_id, stix_id, name, tactic, description, platforms,
            is_subtechnique, parent_id, is_deprecated, is_revoked, mitre_version
        FROM attack_techniques
        WHERE mitre_id IS NOT NULL
        ORDER BY mitre_id
        LIMIT %s OFFSET %s
        """
        return sf.execute_query(sql, (batch_size, offset))
    sql = """
    SELECT
        mitre_id, stix_id, name, tactic, description, platforms,
        is_subtechnique, parent_id, is_deprecated, is_revoked, mitre_version
    FROM attack_techniques
    WHERE mitre_id IS NOT NULL
      AND COALESCE(loaded_to_neo4j, FALSE) = FALSE
    ORDER BY mitre_id
    LIMIT %s
    """
    return sf.execute_query(sql, (batch_size,))


def _mark_techniques_synced(mitre_ids: list[str]) -> None:
    if not mitre_ids:
        return
    sf = get_snowflake_service()
    ph = ",".join(["%s"] * len(mitre_ids))
    with sf.cursor() as cur:
        cur.execute(
            f"""
            UPDATE attack_techniques
            SET loaded_to_neo4j = TRUE
            WHERE mitre_id IN ({ph})
            """,
            tuple(mitre_ids),
        )


def run_attack_techniques_sync(
    *,
    batch_size: int = 500,
    full: bool = False,
    neo4j_database: str | None = None,
    max_batches: int | None = None,
) -> dict[str, Any]:
    """
    MERGE ``(:Technique {id: mitre_id})`` from Snowflake ``attack_techniques`` and set
    ``loaded_to_neo4j`` when successful.

    Incremental (default): rows with ``loaded_to_neo4j = FALSE``.
    Full: LIMIT/OFFSET over all techniques (still updates Snowflake flags).
    """
    if batch_size < 1:
        batch_size = 1
    db = _resolved_neo4j_database(neo4j_database)

    def ensure_tech_constraint(tx: Any) -> None:
        tx.run(_ENSURE_TECHNIQUE_CONSTRAINT)

    _neo4j_write_transaction(ensure_tech_constraint, database=db)

    total = 0
    batches = 0
    offset = 0

    while True:
        if max_batches is not None and batches >= max_batches:
            break
        rows = _fetch_technique_batch(batch_size, full=full, offset=offset)
        if not rows:
            break
        neo_rows = [_technique_to_neo_row(r) for r in rows if r.get("mitre_id")]

        def work(tx: Any) -> None:
            if neo_rows:
                tx.run(_MERGE_TECHNIQUE_BATCH, rows=neo_rows)

        try:
            _neo4j_write_transaction(work, database=db)
        except Exception:
            logger.exception("Neo4j technique sync failed at batch %s", batches + 1)
            raise

        ids = [str(r["mitre_id"]) for r in rows if r.get("mitre_id")]
        _mark_techniques_synced(ids)

        total += len(neo_rows)
        batches += 1
        if full:
            offset += len(rows)
        logger.info(
            "attack_techniques_sync batch=%s rows=%s full=%s",
            batches,
            len(neo_rows),
            full,
        )

    return {
        "batches": batches,
        "techniques_merged": total,
        "full_scan": full,
        "neo4j_database": db or "default",
    }


def _fetch_chunk_batch(batch_size: int, offset: int) -> list[dict[str, Any]]:
    sf = get_snowflake_service()
    sql = """
    SELECT chunk_id, cve_ids, mitre_tech_ids
    FROM advisory_chunks
    WHERE ARRAY_SIZE(cve_ids) > 0
      AND ARRAY_SIZE(mitre_tech_ids) > 0
    ORDER BY chunk_id
    LIMIT %s OFFSET %s
    """
    return sf.execute_query(sql, (batch_size, offset))


def _pairs_from_chunk_row(row: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    cves = row.get("cve_ids") or []
    techs = row.get("mitre_tech_ids") or []
    if not isinstance(cves, (list, tuple)):
        cves = []
    if not isinstance(techs, (list, tuple)):
        techs = []
    for c in cves:
        cve = str(c).strip().upper()
        if not cve.startswith("CVE-"):
            continue
        for m in techs:
            mid = str(m).strip().upper()
            if not mid.startswith("T"):
                continue
            out.append((cve, mid[:20]))
    return out


def run_chunk_technique_link_sync(
    *,
    batch_size: int = 200,
    neo4j_database: str | None = None,
    max_batches: int | None = None,
) -> dict[str, Any]:
    """
    Create ``(:CVE)-[:REFERENCES_TECHNIQUE]->(:Technique)`` edges from rows where the
    same ``advisory_chunks`` row lists both ``cve_ids`` and ``mitre_tech_ids`` (co-occurrence).

    Idempotent MERGE; safe to re-run. Does not write back to Snowflake (no per-chunk flag).
    """
    if batch_size < 1:
        batch_size = 1
    db = _resolved_neo4j_database(neo4j_database)
    offset = 0
    batches = 0
    total_pairs = 0
    seen: set[tuple[str, str]] = set()

    while True:
        if max_batches is not None and batches >= max_batches:
            break
        rows = _fetch_chunk_batch(batch_size, offset)
        if not rows:
            break
        batch_pairs: list[dict[str, str]] = []
        for row in rows:
            for cve_id, mitre_id in _pairs_from_chunk_row(row):
                key = (cve_id, mitre_id)
                if key in seen:
                    continue
                seen.add(key)
                batch_pairs.append({"cve_id": cve_id, "mitre_id": mitre_id})
        if batch_pairs:

            def work(tx: Any) -> None:
                tx.run(_MERGE_CHUNK_TECHNIQUE_RELS, rows=batch_pairs)

            try:
                _neo4j_write_transaction(work, database=db)
            except Exception:
                logger.exception(
                    "Neo4j chunk technique link sync failed at offset=%s", offset
                )
                raise
            total_pairs += len(batch_pairs)

        batches += 1
        offset += batch_size
        logger.info(
            "chunk_technique_link_sync batch=%s offset=%s pairs_this_batch=%s",
            batches,
            offset,
            len(batch_pairs),
        )

    return {
        "batches": batches,
        "unique_pairs_merged": total_pairs,
        "neo4j_database": db or "default",
    }
