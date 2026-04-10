"""Phase 5 — bulk CWE catalog load into Snowflake (report Task 5.1)."""

from __future__ import annotations

from pathlib import Path

from ingestion.cwe.snowflake_load import load_cwe_records_to_snowflake
from ingestion.cwe.transform import transform_catalog_to_records


def load_cwe_records(filepath: str | Path) -> int:
    """
    One-time or infrequent bulk load from a MITRE-style catalog JSON file into
    cwe_records (MERGE insert-only for new cwe_id). Deprecated weaknesses are
    skipped. Typical sources: cwec_catalog.json from fetch_cwe_catalog.py or
    cwec_v4.16.json with a top-level weaknesses[] array.

    Returns the number of rows processed (same as load_cwe_records_to_snowflake).
    """
    records = transform_catalog_to_records(filepath)
    return load_cwe_records_to_snowflake(records)
