"""NDJSON staging for NVD raw and curated rows (local paths or s3:// URIs)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable, Iterator

from ingestion.nvd.s3_io import is_s3_uri, s3_iter_text_lines, s3_upload_file
from ingestion.nvd.transform import transform_vulnerability


def _json_default(obj: Any) -> str:
    if isinstance(obj, (date, datetime)):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def iter_raw_ndjson(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield one NVD vulnerability dict per non-empty line (local file only)."""
    p = Path(path)
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def iter_raw_ndjson_uri(path_or_uri: str | Path) -> Iterator[dict[str, Any]]:
    """Local path or s3:// URI: yield raw vulnerability dicts per line."""
    s = str(path_or_uri)
    if is_s3_uri(s):
        for line in s3_iter_text_lines(s):
            yield json.loads(line)
        return
    yield from iter_raw_ndjson(path_or_uri)


def _raw_line_iterator(in_path: str | Path) -> Iterator[str]:
    s = str(in_path)
    if is_s3_uri(s):
        yield from s3_iter_text_lines(s)
        return
    with Path(in_path).open(encoding="utf-8") as fin:
        for line in fin:
            yield line


def _run_transform_lines(
    line_iter: Iterator[str],
    write_curated_line: Callable[[str], None],
    *,
    log_skips: bool,
) -> dict[str, int]:
    lines_in = 0
    transformed = 0
    skipped = 0
    for line in line_iter:
        line = line.strip()
        if not line:
            continue
        lines_in += 1
        try:
            raw = json.loads(line)
            rec = transform_vulnerability(raw)
            write_curated_line(
                json.dumps(rec, ensure_ascii=False, default=_json_default) + "\n"
            )
            transformed += 1
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            skipped += 1
            if log_skips:
                print(f"skip line {lines_in}: {e}", file=sys.stderr)
    return {"lines_in": lines_in, "transformed": transformed, "skipped": skipped}


def transform_raw_ndjson_to_curated(
    in_path: str | Path,
    out_path: str | Path,
    *,
    log_skips: bool = True,
) -> dict[str, int]:
    """
    Read raw NDJSON lines, transform to cve_records-shaped dicts, write curated NDJSON.
    Supports local paths and s3:// URIs for input and/or output.

    When writing to S3, the worker writes a temporary local NDJSON file then uploads
    (see README for temp disk usage).
    Returns {"lines_in", "transformed", "skipped"}.
    """
    out_s = str(out_path)
    out_s3 = is_s3_uri(out_s)

    if not out_s3:
        outp = Path(out_path)
        outp.parent.mkdir(parents=True, exist_ok=True)
        with outp.open("w", encoding="utf-8") as fout:
            return _run_transform_lines(
                _raw_line_iterator(in_path),
                fout.write,
                log_skips=log_skips,
            )

    fd, tmp_path = tempfile.mkstemp(suffix=".ndjson", text=True)
    os.close(fd)
    try:
        with Path(tmp_path).open("w", encoding="utf-8") as fout:
            stats = _run_transform_lines(
                _raw_line_iterator(in_path),
                fout.write,
                log_skips=log_skips,
            )
        s3_upload_file(
            tmp_path,
            out_s,
            content_type="application/x-ndjson",
        )
        return stats
    finally:
        os.unlink(tmp_path)


def rehydrate_curated_row(d: dict[str, Any]) -> dict[str, Any]:
    """Convert ISO date/time strings back to Python date/datetime for Snowflake binds."""
    out = dict(d)
    pd = out.get("published_date")
    if isinstance(pd, str):
        out["published_date"] = date.fromisoformat(pd[:10])
    lm = out.get("last_modified")
    if isinstance(lm, str):
        t = lm.strip()
        if t.endswith("Z"):
            t = t[:-1] + "+00:00"
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is not None:
            from datetime import timezone

            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        out["last_modified"] = dt
    return out


def iter_curated_ndjson(path_or_uri: str | Path) -> Iterator[dict[str, Any]]:
    """Yield rehydrated row dicts from curated NDJSON (local path or s3:// URI)."""
    s = str(path_or_uri)
    if is_s3_uri(s):
        for line in s3_iter_text_lines(s):
            d = json.loads(line)
            yield rehydrate_curated_row(d)
        return

    p = Path(path_or_uri)
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            yield rehydrate_curated_row(d)
