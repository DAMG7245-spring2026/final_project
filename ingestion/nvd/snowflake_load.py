"""MERGE upsert NVD rows into cve_records (does not touch KEV columns)."""

from __future__ import annotations

import json
import tempfile
from os import unlink
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.services.snowflake import get_snowflake_service
from ingestion.nvd.storage import iter_curated_ndjson

_STAGING_TABLE = "cve_records_staging"
_STAGING_STAGE = "cve_records_staging_stage"
_MAP_STAGING_TABLE = "cve_cwe_mappings_staging"
_MAP_STAGING_STAGE = "cve_cwe_mappings_staging_stage"

CREATE_STAGING_SQL = f"""
CREATE TEMP TABLE IF NOT EXISTS {_STAGING_TABLE} (
    cve_id VARCHAR,
    source_identifier VARCHAR,
    published_date DATE,
    last_modified TIMESTAMP_NTZ,
    vuln_status VARCHAR,
    description_en VARCHAR,
    cvss_version VARCHAR,
    cvss_score FLOAT,
    cvss_severity VARCHAR,
    attack_vector VARCHAR,
    attack_complexity VARCHAR,
    privileges_required VARCHAR,
    user_interaction VARCHAR,
    scope VARCHAR,
    confidentiality_impact VARCHAR,
    integrity_impact VARCHAR,
    exploitability_score FLOAT,
    impact_score FLOAT,
    cwe_ids ARRAY,
    cpe_matches VARIANT,
    has_exploit_ref BOOLEAN,
    raw_json VARIANT
)
"""

TRUNCATE_STAGING_SQL = f"TRUNCATE TABLE {_STAGING_TABLE}"

CREATE_STAGE_SQL = f"CREATE TEMP STAGE IF NOT EXISTS {_STAGING_STAGE}"

COPY_INTO_STAGING_SQL_TMPL = f"""
COPY INTO {_STAGING_TABLE} (
    cve_id,
    source_identifier,
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
    exploitability_score,
    impact_score,
    cwe_ids,
    cpe_matches,
    has_exploit_ref,
    raw_json
)
FROM (
    SELECT
        $1:cve_id::VARCHAR,
        $1:source_identifier::VARCHAR,
        $1:published_date::DATE,
        $1:last_modified::TIMESTAMP_NTZ,
        $1:vuln_status::VARCHAR,
        $1:description_en::VARCHAR,
        $1:cvss_version::VARCHAR,
        $1:cvss_score::FLOAT,
        $1:cvss_severity::VARCHAR,
        $1:attack_vector::VARCHAR,
        $1:attack_complexity::VARCHAR,
        $1:privileges_required::VARCHAR,
        $1:user_interaction::VARCHAR,
        $1:scope::VARCHAR,
        $1:confidentiality_impact::VARCHAR,
        $1:integrity_impact::VARCHAR,
        $1:exploitability_score::FLOAT,
        $1:impact_score::FLOAT,
        CAST($1:cwe_ids AS ARRAY),
        $1:cpe_matches,
        $1:has_exploit_ref::BOOLEAN,
        $1:raw_json
    FROM {{stage_path}}
)
FILE_FORMAT = (TYPE = JSON STRIP_OUTER_ARRAY = FALSE)
PURGE = TRUE
"""

MERGE_FROM_STAGING_SQL = f"""
MERGE INTO cve_records AS t
USING {_STAGING_TABLE} AS s
ON t.cve_id = s.cve_id
WHEN MATCHED THEN UPDATE SET
    t.source_identifier = s.source_identifier,
    t.published_date = s.published_date,
    t.last_modified = s.last_modified,
    t.vuln_status = s.vuln_status,
    t.description_en = s.description_en,
    t.cvss_version = s.cvss_version,
    t.cvss_score = s.cvss_score,
    t.cvss_severity = s.cvss_severity,
    t.attack_vector = s.attack_vector,
    t.attack_complexity = s.attack_complexity,
    t.privileges_required = s.privileges_required,
    t.user_interaction = s.user_interaction,
    t.scope = s.scope,
    t.confidentiality_impact = s.confidentiality_impact,
    t.integrity_impact = s.integrity_impact,
    t.exploitability_score = s.exploitability_score,
    t.impact_score = s.impact_score,
    t.cwe_ids = s.cwe_ids,
    t.cpe_matches = s.cpe_matches,
    t.has_exploit_ref = s.has_exploit_ref,
    t.raw_json = s.raw_json
WHEN NOT MATCHED THEN
    INSERT (
        cve_id,
        source_identifier,
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
        exploitability_score,
        impact_score,
        cwe_ids,
        cpe_matches,
        has_exploit_ref,
        raw_json
    )
    VALUES (
        s.cve_id,
        s.source_identifier,
        s.published_date,
        s.last_modified,
        s.vuln_status,
        s.description_en,
        s.cvss_version,
        s.cvss_score,
        s.cvss_severity,
        s.attack_vector,
        s.attack_complexity,
        s.privileges_required,
        s.user_interaction,
        s.scope,
        s.confidentiality_impact,
        s.integrity_impact,
        s.exploitability_score,
        s.impact_score,
        s.cwe_ids,
        s.cpe_matches,
        s.has_exploit_ref,
        s.raw_json
    )
"""

CREATE_CVE_CWE_MAP_STAGING_SQL = f"""
CREATE TEMP TABLE IF NOT EXISTS {_MAP_STAGING_TABLE} (
    mapping_id VARCHAR,
    cve_id VARCHAR,
    cwe_id VARCHAR,
    mapping_source VARCHAR,
    mapping_type VARCHAR
)
"""

TRUNCATE_CVE_CWE_MAP_STAGING_SQL = f"TRUNCATE TABLE {_MAP_STAGING_TABLE}"
CREATE_CVE_CWE_MAP_STAGE_SQL = f"CREATE TEMP STAGE IF NOT EXISTS {_MAP_STAGING_STAGE}"

COPY_INTO_CVE_CWE_MAP_STAGING_SQL_TMPL = f"""
COPY INTO {_MAP_STAGING_TABLE} (
    mapping_id,
    cve_id,
    cwe_id,
    mapping_source,
    mapping_type
)
FROM (
    SELECT
        $1:mapping_id::VARCHAR,
        $1:cve_id::VARCHAR,
        $1:cwe_id::VARCHAR,
        $1:mapping_source::VARCHAR,
        $1:mapping_type::VARCHAR
    FROM {{stage_path}}
)
FILE_FORMAT = (TYPE = JSON STRIP_OUTER_ARRAY = FALSE)
PURGE = TRUE
"""

MERGE_CVE_CWE_MAPPINGS_SQL = f"""
MERGE INTO cve_cwe_mappings AS t
USING {_MAP_STAGING_TABLE} AS s
ON t.mapping_id = s.mapping_id
WHEN MATCHED THEN UPDATE SET
    t.cve_id = s.cve_id,
    t.cwe_id = s.cwe_id,
    t.mapping_source = s.mapping_source,
    t.mapping_type = s.mapping_type
WHEN NOT MATCHED THEN
    INSERT (
        mapping_id,
        cve_id,
        cwe_id,
        mapping_source,
        mapping_type
    )
    VALUES (
        s.mapping_id,
        s.cve_id,
        s.cwe_id,
        s.mapping_source,
        s.mapping_type
    )
"""


def _row_params(r: dict[str, Any]) -> tuple[Any, ...]:
    cwe_json = json.dumps(r.get("cwe_ids") or [])
    cpe_json = json.dumps(r.get("cpe_matches") or [])
    raw_json = json.dumps(r.get("raw_json") or {}, ensure_ascii=False)
    return (
        r["cve_id"],
        r.get("source_identifier"),
        r["published_date"],
        r["last_modified"],
        r.get("vuln_status") or "",
        r.get("description_en") or "",
        r.get("cvss_version"),
        r.get("cvss_score"),
        r.get("cvss_severity"),
        r.get("attack_vector"),
        r.get("attack_complexity"),
        r.get("privileges_required"),
        r.get("user_interaction"),
        r.get("scope"),
        r.get("confidentiality_impact"),
        r.get("integrity_impact"),
        r.get("exploitability_score"),
        r.get("impact_score"),
        cwe_json,
        cpe_json,
        r.get("has_exploit_ref", False),
        raw_json,
    )


def _staging_row(r: dict[str, Any]) -> dict[str, Any]:
    published_date = r["published_date"]
    if hasattr(published_date, "isoformat"):
        published_date = published_date.isoformat()
    last_modified = r["last_modified"]
    if hasattr(last_modified, "isoformat"):
        last_modified = last_modified.isoformat()
    return {
        "cve_id": r["cve_id"],
        "source_identifier": r.get("source_identifier"),
        "published_date": published_date,
        "last_modified": last_modified,
        "vuln_status": r.get("vuln_status") or "",
        "description_en": r.get("description_en") or "",
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
        "exploitability_score": r.get("exploitability_score"),
        "impact_score": r.get("impact_score"),
        "cwe_ids": r.get("cwe_ids") or [],
        "cpe_matches": r.get("cpe_matches") or [],
        "has_exploit_ref": bool(r.get("has_exploit_ref", False)),
        "raw_json": r.get("raw_json") or {},
    }


def _write_batch_jsonl(records: list[dict[str, Any]]) -> Path:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        for record in records:
            f.write(json.dumps(_staging_row(record), ensure_ascii=False) + "\n")
        return Path(f.name)


def _mapping_rows(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        cve_id = str(record.get("cve_id") or "").strip()
        if not cve_id:
            continue
        for cwe in record.get("cwe_ids") or []:
            cwe_id = str(cwe or "").strip()[:20]
            if not cwe_id:
                continue
            key = (cve_id, cwe_id)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "mapping_id": f"{cve_id}|{cwe_id}|nvd",
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "mapping_source": "nvd",
                    "mapping_type": "PrimaryOrSecondary",
                }
            )
    return out


def _write_mapping_batch_jsonl(records: list[dict[str, Any]]) -> Path | None:
    rows = _mapping_rows(records)
    if not rows:
        return None
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return Path(f.name)


def upsert_cve_cwe_mappings(records: list[dict[str, Any]], *, cur: Any | None = None) -> int:
    """
    Upsert normalized CVE->CWE mappings from transformed records.
    """
    mapping_file = _write_mapping_batch_jsonl(records)
    if mapping_file is None:
        return 0
    stage_file = f"batch_{uuid4().hex}.jsonl"
    put_path = str(mapping_file.resolve()).replace("\\", "\\\\")
    put_sql = (
        f"PUT 'file://{put_path}' @{_MAP_STAGING_STAGE}/{stage_file} "
        "AUTO_COMPRESS=FALSE OVERWRITE=TRUE"
    )
    copy_sql = COPY_INTO_CVE_CWE_MAP_STAGING_SQL_TMPL.format(
        stage_path=f"@{_MAP_STAGING_STAGE}/{stage_file}"
    )
    owns_cursor = cur is None
    if owns_cursor:
        sf = get_snowflake_service()
        ctx = sf.cursor()
        cur = ctx.__enter__()
    assert cur is not None
    try:
        cur.execute(CREATE_CVE_CWE_MAP_STAGING_SQL)
        cur.execute(CREATE_CVE_CWE_MAP_STAGE_SQL)
        cur.execute(TRUNCATE_CVE_CWE_MAP_STAGING_SQL)
        cur.execute(put_sql)
        cur.execute(copy_sql)
        cur.execute(MERGE_CVE_CWE_MAPPINGS_SQL)
    finally:
        if owns_cursor:
            ctx.__exit__(None, None, None)
        try:
            unlink(mapping_file)
        except OSError:
            pass
    return len(_mapping_rows(records))


def upsert_cve_records_from_curated_ndjson(
    path: str | Path,
    batch_size: int = 200,
) -> dict[str, int]:
    """
    Stream curated NDJSON from a local path or s3:// URI; upsert in batches to cap memory.
    Each line is one row dict (ISO dates); rehydrates before MERGE.
    """
    batch_size = max(1, batch_size)
    lines_read = 0
    rows_upserted = 0
    mappings_upserted = 0
    batches = 0
    batch: list[dict[str, Any]] = []
    for row in iter_curated_ndjson(path):
        lines_read += 1
        batch.append(row)
        if len(batch) >= batch_size:
            rows_upserted += upsert_cve_records(batch)
            mappings_upserted += len(_mapping_rows(batch))
            batches += 1
            batch = []
    if batch:
        rows_upserted += upsert_cve_records(batch)
        mappings_upserted += len(_mapping_rows(batch))
        batches += 1
    return {
        "lines_read": lines_read,
        "rows_upserted": rows_upserted,
        "mappings_upserted": mappings_upserted,
        "batches": batches,
    }


def upsert_cve_records(records: list[dict[str, Any]]) -> int:
    """
    MERGE each record into cve_records. Updates NVD-owned columns only on match;
    never modifies is_kev or kev_* columns.
    """
    if not records:
        return 0
    sf = get_snowflake_service()
    batch_file = _write_batch_jsonl(records)
    stage_file = f"batch_{uuid4().hex}.jsonl"
    put_path = str(batch_file.resolve()).replace("\\", "\\\\")
    put_sql = (
        f"PUT 'file://{put_path}' @{_STAGING_STAGE}/{stage_file} "
        "AUTO_COMPRESS=FALSE OVERWRITE=TRUE"
    )
    copy_sql = COPY_INTO_STAGING_SQL_TMPL.format(
        stage_path=f"@{_STAGING_STAGE}/{stage_file}"
    )
    with sf.cursor() as cur:
        try:
            cur.execute(CREATE_STAGING_SQL)
            cur.execute(CREATE_STAGE_SQL)
            cur.execute(TRUNCATE_STAGING_SQL)
            cur.execute(put_sql)
            cur.execute(copy_sql)
            cur.execute(MERGE_FROM_STAGING_SQL)
            upsert_cve_cwe_mappings(records, cur=cur)
        finally:
            try:
                unlink(batch_file)
            except OSError:
                pass
    return len(records)
