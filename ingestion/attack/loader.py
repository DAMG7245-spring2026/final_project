"""Load transformed MITRE ATT&CK rows into Snowflake."""

from __future__ import annotations

import json
import tempfile
from os import unlink
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.services.snowflake import get_snowflake_service

_SPECS = {
    "attack_techniques": {
        "pk": "mitre_id",
        "columns": [
            "mitre_id",
            "stix_id",
            "name",
            "tactic",
            "description",
            "platforms",
            "is_subtechnique",
            "parent_id",
            "is_deprecated",
            "is_revoked",
            "mitre_version",
        ],
        "types": [
            "VARCHAR",
            "VARCHAR",
            "VARCHAR",
            "VARCHAR",
            "VARCHAR",
            "ARRAY",
            "BOOLEAN",
            "VARCHAR",
            "BOOLEAN",
            "BOOLEAN",
            "VARCHAR",
        ],
        "copy_select": [
            "$1:mitre_id::VARCHAR",
            "$1:stix_id::VARCHAR",
            "$1:name::VARCHAR",
            "$1:tactic::VARCHAR",
            "$1:description::VARCHAR",
            "CAST($1:platforms AS ARRAY)",
            "$1:is_subtechnique::BOOLEAN",
            "$1:parent_id::VARCHAR",
            "$1:is_deprecated::BOOLEAN",
            "$1:is_revoked::BOOLEAN",
            "$1:mitre_version::VARCHAR",
        ],
    },
    "attack_actors": {
        "pk": "actor_name",
        "columns": [
            "actor_name",
            "stix_id",
            "external_id",
            "aliases",
            "country",
            "motivation",
            "description",
            "target_sectors",
        ],
        "types": ["VARCHAR", "VARCHAR", "VARCHAR", "ARRAY", "VARCHAR", "VARCHAR", "VARCHAR", "ARRAY"],
        "copy_select": [
            "$1:actor_name::VARCHAR",
            "$1:stix_id::VARCHAR",
            "$1:external_id::VARCHAR",
            "CAST($1:aliases AS ARRAY)",
            "$1:country::VARCHAR",
            "$1:motivation::VARCHAR",
            "$1:description::VARCHAR",
            "CAST($1:target_sectors AS ARRAY)",
        ],
    },
    "attack_mitigations": {
        "pk": "mitigation_id",
        "columns": ["mitigation_id", "stix_id", "name", "description"],
        "types": ["VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR"],
        "copy_select": [
            "$1:mitigation_id::VARCHAR",
            "$1:stix_id::VARCHAR",
            "$1:name::VARCHAR",
            "$1:description::VARCHAR",
        ],
    },
    "attack_tactics": {
        "pk": "tactic_id",
        "columns": ["tactic_id", "stix_id", "name", "shortname", "description", "tactic_order"],
        "types": ["VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "INTEGER"],
        "copy_select": [
            "$1:tactic_id::VARCHAR",
            "$1:stix_id::VARCHAR",
            "$1:name::VARCHAR",
            "$1:shortname::VARCHAR",
            "$1:description::VARCHAR",
            "$1:tactic_order::INTEGER",
        ],
    },
    "attack_campaigns": {
        "pk": "campaign_id",
        "columns": ["campaign_id", "stix_id", "external_id", "name", "description"],
        "types": ["VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR"],
        "copy_select": [
            "$1:campaign_id::VARCHAR",
            "$1:stix_id::VARCHAR",
            "$1:external_id::VARCHAR",
            "$1:name::VARCHAR",
            "$1:description::VARCHAR",
        ],
    },
    "attack_relationships": {
        "pk": "relationship_id",
        "columns": [
            "relationship_id",
            "source_stix_id",
            "source_name",
            "source_type",
            "target_stix_id",
            "target_name",
            "target_type",
            "relation_type",
        ],
        "types": ["VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR"],
        "copy_select": [
            "$1:relationship_id::VARCHAR",
            "$1:source_stix_id::VARCHAR",
            "$1:source_name::VARCHAR",
            "$1:source_type::VARCHAR",
            "$1:target_stix_id::VARCHAR",
            "$1:target_name::VARCHAR",
            "$1:target_type::VARCHAR",
            "$1:relation_type::VARCHAR",
        ],
    },
}


def _normalize_row(row: dict[str, Any], columns: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for c in columns:
        v = row.get(c)
        if isinstance(v, (list, dict)):
            out[c] = v
        elif isinstance(v, bool) or v is None:
            out[c] = v
        else:
            out[c] = str(v) if v is not None else None
    return out


def _write_jsonl(rows: list[dict[str, Any]], columns: list[str]) -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(_normalize_row(row, columns), ensure_ascii=False) + "\n")
        return Path(f.name)


def _create_staging_table_sql(staging_table: str, columns: list[str], types: list[str]) -> str:
    defs = ",\n    ".join(f"{c} {t}" for c, t in zip(columns, types, strict=True))
    return f"CREATE TEMP TABLE IF NOT EXISTS {staging_table} (\n    {defs}\n)"


def _copy_sql(staging_table: str, columns: list[str], copy_select: list[str], stage_path: str) -> str:
    cols = ",\n    ".join(columns)
    selects = ",\n        ".join(copy_select)
    return f"""
COPY INTO {staging_table} (
    {cols}
)
FROM (
    SELECT
        {selects}
    FROM {stage_path}
)
FILE_FORMAT = (TYPE = JSON STRIP_OUTER_ARRAY = FALSE)
PURGE = TRUE
"""


def _merge_sql(target_table: str, staging_table: str, pk: str, columns: list[str]) -> str:
    update_cols = [c for c in columns if c != pk]
    update_set = ",\n    ".join(f"t.{c} = s.{c}" for c in update_cols)
    insert_cols = ", ".join(columns)
    values_cols = ", ".join(f"s.{c}" for c in columns)
    return f"""
MERGE INTO {target_table} AS t
USING {staging_table} AS s
ON t.{pk} = s.{pk}
WHEN MATCHED THEN UPDATE SET
    {update_set}
WHEN NOT MATCHED THEN INSERT ({insert_cols})
VALUES ({values_cols})
"""


def _bulk_merge(cur: Any, table_name: str, rows: list[dict[str, Any]]) -> None:
    spec = _SPECS[table_name]
    columns = spec["columns"]
    types = spec["types"]
    pk = spec["pk"]
    copy_select = spec["copy_select"]
    staging_table = f"{table_name}_staging"
    stage_name = f"{table_name}_stage"

    batch_file = _write_jsonl(rows, columns)
    stage_file = f"batch_{uuid4().hex}.jsonl"
    put_path = str(batch_file.resolve()).replace("\\", "\\\\")
    put_sql = (
        f"PUT 'file://{put_path}' @{stage_name}/{stage_file} "
        "AUTO_COMPRESS=FALSE OVERWRITE=TRUE"
    )
    try:
        cur.execute(_create_staging_table_sql(staging_table, columns, types))
        cur.execute(f"CREATE TEMP STAGE IF NOT EXISTS {stage_name}")
        cur.execute(f"TRUNCATE TABLE {staging_table}")
        cur.execute(put_sql)
        cur.execute(_copy_sql(staging_table, columns, copy_select, f"@{stage_name}/{stage_file}"))
        cur.execute(_merge_sql(table_name, staging_table, pk, columns))
    finally:
        try:
            unlink(batch_file)
        except OSError:
            pass


def upsert_all_attack_tables(
    techniques: list[dict[str, Any]],
    actors: list[dict[str, Any]],
    mitigations: list[dict[str, Any]],
    tactics: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
) -> dict[str, int]:
    """Upsert transformed ATT&CK rows into Snowflake tables using bulk staging."""
    sf = get_snowflake_service()
    with sf.cursor() as cur:
        t_rows = [t for t in techniques if t.get("mitre_id")]
        if t_rows:
            _bulk_merge(cur, "attack_techniques", t_rows)
        a_rows = [a for a in actors if a.get("actor_name")]
        if a_rows:
            _bulk_merge(cur, "attack_actors", a_rows)
        m_rows = [m for m in mitigations if m.get("mitigation_id")]
        if m_rows:
            _bulk_merge(cur, "attack_mitigations", m_rows)
        ta_rows = [t for t in tactics if t.get("tactic_id")]
        if ta_rows:
            _bulk_merge(cur, "attack_tactics", ta_rows)
        c_rows = [c for c in campaigns if c.get("campaign_id")]
        if c_rows:
            _bulk_merge(cur, "attack_campaigns", c_rows)
        if relationships:
            _bulk_merge(cur, "attack_relationships", relationships)
    return {
        "techniques": len(techniques),
        "actors": len(actors),
        "mitigations": len(mitigations),
        "tactics": len(tactics),
        "campaigns": len(campaigns),
        "relationships": len(relationships),
    }
