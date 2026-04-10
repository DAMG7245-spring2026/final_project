"""CWE catalog parse, transform, and optional Snowflake load."""

from ingestion.cwe.loader import load_cwe_records
from ingestion.cwe.snowflake_load import load_cwe_records_to_snowflake
from ingestion.cwe.transform import (
    raw_weaknesses_sample_document,
    transform_catalog_to_records,
    weakness_to_record,
)

__all__ = [
    "load_cwe_records",
    "load_cwe_records_to_snowflake",
    "raw_weaknesses_sample_document",
    "transform_catalog_to_records",
    "weakness_to_record",
]
