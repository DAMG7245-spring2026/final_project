"""S3 helpers for NVD NDJSON staging (s3://bucket/key URIs)."""

from __future__ import annotations

import io
import re
from pathlib import Path
from typing import Iterator

import boto3
from botocore.client import BaseClient

_S3_URI_RE = re.compile(r"^s3://([^/]+)/(.+)$")


def is_s3_uri(path_or_uri: str | Path) -> bool:
    return str(path_or_uri).startswith("s3://")


def parse_s3_uri(uri: str) -> tuple[str, str]:
    """
    Parse s3://bucket/key into (bucket, key). Key may contain slashes.
    Raises ValueError if malformed.
    """
    s = uri.strip()
    m = _S3_URI_RE.match(s)
    if not m:
        raise ValueError(f"Invalid S3 URI (expected s3://bucket/key): {uri!r}")
    bucket, key = m.group(1), m.group(2)
    if not key or key.endswith("/"):
        raise ValueError(f"Invalid S3 URI (missing object key): {uri!r}")
    return bucket, key


def get_s3_client() -> BaseClient:
    from app.config import get_settings

    s = get_settings()
    return boto3.client(
        "s3",
        aws_access_key_id=s.aws_access_key_id or None,
        aws_secret_access_key=s.aws_secret_access_key or None,
        region_name=s.aws_region or None,
    )


def s3_upload_file(local_path: str | Path, s3_uri: str, *, content_type: str | None = None) -> None:
    """Upload a local file to s3://bucket/key."""
    bucket, key = parse_s3_uri(s3_uri)
    cli = get_s3_client()
    if content_type:
        cli.upload_file(
            str(local_path),
            bucket,
            key,
            ExtraArgs={"ContentType": content_type},
        )
    else:
        cli.upload_file(str(local_path), bucket, key)


def list_s3_keys(bucket: str, prefix: str) -> list[str]:
    """
    List object keys under bucket/prefix (paginated). Prefix should not start with /.
    Returns keys sorted lexically (e.g. nvd/raw/2024-01.jsonl).
    """
    p = prefix.strip().lstrip("/")
    if p and not p.endswith("/"):
        p = f"{p}/"
    cli = get_s3_client()
    keys: list[str] = []
    token: str | None = None
    while True:
        kwargs: dict[str, str | int] = {"Bucket": bucket, "Prefix": p, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        resp = cli.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []) or []:
            k = obj.get("Key")
            if k and not str(k).endswith("/"):
                keys.append(str(k))
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")
        if not token:
            break
    keys.sort()
    return keys


def s3_iter_text_lines(s3_uri: str) -> Iterator[str]:
    """Stream newline-separated text lines from an S3 object (UTF-8)."""
    bucket, key = parse_s3_uri(s3_uri)
    resp = get_s3_client().get_object(Bucket=bucket, Key=key)
    body = resp["Body"]
    wrapper = io.TextIOWrapper(body, encoding="utf-8", newline="")
    try:
        for line in wrapper:
            line = line.strip()
            if line:
                yield line
    finally:
        wrapper.detach()
