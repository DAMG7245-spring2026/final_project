"""NVD CVE API 2.0 ingestion (Phase 2)."""

from ingestion.nvd.client import (
    fetch_nvd_delta,
    fetch_nvd_delta_to_ndjson,
    fetch_single_cve,
    resolve_nvd_request_interval,
)
from ingestion.nvd.pipeline import (
    ingest_lastmod_month_to_disk_and_snowflake,
    ingest_lastmod_month_to_s3_and_snowflake,
    load_curated_file_to_snowflake,
    sync_delta,
    sync_single_cve,
    transform_raw_file_to_curated,
)
from ingestion.nvd.snowflake_load import (
    upsert_cve_records,
    upsert_cve_records_from_curated_ndjson,
)
from ingestion.nvd.transform import (
    CveSnowflakeRecord,
    extract_cvss,
    transform_vulnerability,
)

__all__ = [
    "CveSnowflakeRecord",
    "extract_cvss",
    "fetch_nvd_delta",
    "fetch_nvd_delta_to_ndjson",
    "fetch_single_cve",
    "ingest_lastmod_month_to_disk_and_snowflake",
    "ingest_lastmod_month_to_s3_and_snowflake",
    "load_curated_file_to_snowflake",
    "resolve_nvd_request_interval",
    "sync_delta",
    "sync_single_cve",
    "transform_raw_file_to_curated",
    "transform_vulnerability",
    "upsert_cve_records",
    "upsert_cve_records_from_curated_ndjson",
]
