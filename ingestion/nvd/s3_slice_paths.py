"""Deterministic S3 URIs for NVD slice-based raw/curated files (parallel to monthly YYYY-MM layout)."""

from __future__ import annotations

from datetime import date


def slice_raw_s3_uri(bucket: str, prefix: str, start: date, end: date) -> str:
    """``s3://bucket/{prefix}/raw/slices/YYYY-MM-DD_YYYY-MM-DD.jsonl``."""
    p = prefix.strip().strip("/")
    span = f"{start.isoformat()}_{end.isoformat()}"
    return f"s3://{bucket}/{p}/raw/slices/{span}.jsonl"


def slice_curated_s3_uri(bucket: str, prefix: str, start: date, end: date) -> str:
    """``s3://bucket/{prefix}/curated/slices/YYYY-MM-DD_YYYY-MM-DD.ndjson``."""
    p = prefix.strip().strip("/")
    span = f"{start.isoformat()}_{end.isoformat()}"
    return f"s3://{bucket}/{p}/curated/slices/{span}.ndjson"
