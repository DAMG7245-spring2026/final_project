"""Orchestrate NVD fetch -> transform -> Snowflake upsert."""

from __future__ import annotations

import calendar
import os
import tempfile
from datetime import date
from pathlib import Path
from typing import Any

from ingestion.nvd.client import (
    fetch_nvd_delta,
    fetch_nvd_delta_to_ndjson,
    fetch_single_cve,
    fetch_single_cve_to_ndjson,
)
from ingestion.nvd.s3_io import is_s3_uri, s3_upload_file
from ingestion.nvd.snowflake_load import (
    upsert_cve_records,
    upsert_cve_records_from_curated_ndjson,
)
from ingestion.nvd.storage import transform_raw_ndjson_to_curated
from ingestion.nvd.transform import transform_vulnerability


def _api_key(explicit: str | None) -> str | None:
    if explicit:
        return explicit.strip() or None
    from app.config import get_settings

    k = (get_settings().nvd_api_key or "").strip()
    return k or None


def sync_delta(
    start_date: date,
    end_date: date,
    api_key: str | None = None,
    *,
    client: Any = None,
    explicit_interval: float | None = None,
) -> dict[str, int]:
    """
    Fetch modified CVEs in range, transform, upsert. Returns counts.
    """
    key = _api_key(api_key)
    raw = fetch_nvd_delta(
        start_date, end_date, key, client=client, explicit_interval=explicit_interval
    )
    records = []
    for item in raw:
        try:
            records.append(transform_vulnerability(item))
        except (KeyError, ValueError, TypeError):
            continue
    upserted = upsert_cve_records(records)
    return {"fetched": len(raw), "transformed": len(records), "upserted": upserted}


def sync_single_cve(
    cve_id: str,
    api_key: str | None = None,
    *,
    client: Any = None,
) -> dict[str, int]:
    key = _api_key(api_key)
    item = fetch_single_cve(cve_id, key, client=client)
    if not item:
        return {"fetched": 0, "transformed": 0, "upserted": 0}
    rec = transform_vulnerability(item)
    n = upsert_cve_records([rec])
    return {"fetched": 1, "transformed": 1, "upserted": n}


def fetch_delta_to_raw_file(
    start_date: date,
    end_date: date,
    raw_out: str | Path,
    api_key: str | None = None,
    *,
    client: Any = None,
    explicit_interval: float | None = None,
) -> dict[str, int]:
    key = _api_key(api_key)
    raw_s = str(raw_out)
    if is_s3_uri(raw_s):
        fd, tmp_path = tempfile.mkstemp(suffix=".jsonl", text=True)
        os.close(fd)
        try:
            stats = fetch_nvd_delta_to_ndjson(
                start_date,
                end_date,
                tmp_path,
                key,
                client=client,
                explicit_interval=explicit_interval,
            )
            s3_upload_file(tmp_path, raw_s, content_type="application/x-ndjson")
            return {"fetched": stats["written"], "pages": stats["pages"]}
        finally:
            os.unlink(tmp_path)
    stats = fetch_nvd_delta_to_ndjson(
        start_date,
        end_date,
        raw_out,
        key,
        client=client,
        explicit_interval=explicit_interval,
    )
    return {"fetched": stats["written"], "pages": stats["pages"]}


def fetch_cve_to_raw_file(
    cve_id: str,
    raw_out: str | Path,
    api_key: str | None = None,
    *,
    client: Any = None,
) -> dict[str, int]:
    key = _api_key(api_key)
    raw_s = str(raw_out)
    if is_s3_uri(raw_s):
        fd, tmp_path = tempfile.mkstemp(suffix=".jsonl", text=True)
        os.close(fd)
        try:
            stats = fetch_single_cve_to_ndjson(cve_id, tmp_path, key, client=client)
            s3_upload_file(tmp_path, raw_s, content_type="application/x-ndjson")
            return {"fetched": stats["written"], "pages": stats["pages"]}
        finally:
            os.unlink(tmp_path)
    return fetch_single_cve_to_ndjson(cve_id, raw_out, key, client=client)


def transform_raw_file_to_curated(
    raw_in: str | Path,
    curated_out: str | Path,
) -> dict[str, int]:
    return transform_raw_ndjson_to_curated(raw_in, curated_out)


def load_curated_file_to_snowflake(
    curated_in: str | Path,
    batch_size: int = 200,
) -> dict[str, int]:
    return upsert_cve_records_from_curated_ndjson(curated_in, batch_size=batch_size)


def ingest_lastmod_month_to_disk_and_snowflake(
    year: int,
    month: int,
    *,
    base_dir: str | Path | None = None,
    snowflake_batch_size: int = 2000,
    api_key: str | None = None,
    client: Any = None,
    explicit_interval: float | None = None,
) -> dict[str, Any]:
    """
    One calendar month of NVD lastModified activity: raw NDJSON, curated NDJSON,
    then Snowflake MERGE. Paths: {base_dir}/raw/YYYY-MM.jsonl and
    {base_dir}/curated/YYYY-MM.ndjson.

    Default base_dir is ./data/nvd relative to cwd; Airflow should pass an
    absolute path (e.g. repo_root / "data" / "nvd").
    """
    start_date = date(year, month, 1)
    last_d = calendar.monthrange(year, month)[1]
    end_date = date(year, month, last_d)

    base = Path(base_dir) if base_dir is not None else Path("data") / "nvd"
    raw_dir = base / "raw"
    curated_dir = base / "curated"
    raw_dir.mkdir(parents=True, exist_ok=True)
    curated_dir.mkdir(parents=True, exist_ok=True)

    ym = f"{year:04d}-{month:02d}"
    raw_path = raw_dir / f"{ym}.jsonl"
    curated_path = curated_dir / f"{ym}.ndjson"

    fetch_stats = fetch_delta_to_raw_file(
        start_date,
        end_date,
        raw_path,
        api_key,
        client=client,
        explicit_interval=explicit_interval,
    )
    transform_stats = transform_raw_file_to_curated(raw_path, curated_path)
    load_stats = load_curated_file_to_snowflake(
        curated_path, batch_size=snowflake_batch_size
    )

    return {
        "year": year,
        "month": month,
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "raw_path": str(raw_path.resolve()),
        "curated_path": str(curated_path.resolve()),
        "fetch": fetch_stats,
        "transform": transform_stats,
        "load": load_stats,
    }


def ingest_lastmod_month_to_s3_and_snowflake(
    year: int,
    month: int,
    *,
    bucket: str | None = None,
    prefix: str = "nvd",
    snowflake_batch_size: int = 2000,
    api_key: str | None = None,
    client: Any = None,
    explicit_interval: float | None = None,
) -> dict[str, Any]:
    """
    One calendar month of NVD lastModified activity: raw NDJSON to S3, curated NDJSON
    to S3, then Snowflake MERGE from the curated object.

    Objects:
      s3://{bucket}/{prefix}/raw/YYYY-MM.jsonl
      s3://{bucket}/{prefix}/curated/YYYY-MM.ndjson

    Bucket: pass ``bucket`` or set ``S3_BUCKET`` in the environment (via Settings).
    """
    from app.config import get_settings

    b = (bucket or get_settings().s3_bucket or "").strip()
    if not b:
        raise ValueError(
            "S3 bucket is required: pass bucket=... or set S3_BUCKET in the environment."
        )

    start_date = date(year, month, 1)
    last_d = calendar.monthrange(year, month)[1]
    end_date = date(year, month, last_d)
    ym = f"{year:04d}-{month:02d}"
    raw_uri = f"s3://{b}/{prefix}/raw/{ym}.jsonl"
    curated_uri = f"s3://{b}/{prefix}/curated/{ym}.ndjson"

    fetch_stats = fetch_delta_to_raw_file(
        start_date,
        end_date,
        raw_uri,
        api_key,
        client=client,
        explicit_interval=explicit_interval,
    )
    transform_stats = transform_raw_file_to_curated(raw_uri, curated_uri)
    load_stats = load_curated_file_to_snowflake(
        curated_uri, batch_size=snowflake_batch_size
    )

    return {
        "year": year,
        "month": month,
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "raw_uri": raw_uri,
        "curated_uri": curated_uri,
        "fetch": fetch_stats,
        "transform": transform_stats,
        "load": load_stats,
    }
