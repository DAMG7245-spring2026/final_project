#!/usr/bin/env python3
"""
NVD CVE API 2.0 — local staging then Snowflake (Phase 2).

  # 1) Fetch to NDJSON (raw NVD vulnerability objects, one per line)
  poetry run python scripts/nvd_ingest.py fetch --start 2024-01-01 --end 2024-01-07 \\
    --raw-out data/nvd/raw/2024-01.jsonl
  poetry run python scripts/nvd_ingest.py fetch --cve CVE-2024-21413 --raw-out data/nvd/raw/cve.jsonl

  # 2) Transform to curated NDJSON (cve_records-shaped rows)
  poetry run python scripts/nvd_ingest.py transform --raw-in data/nvd/raw/2024-01.jsonl \\
    --curated-out data/nvd/curated/2024-01.ndjson

  # 3) Load curated file to Snowflake in batches (local path or s3://bucket/.../file.ndjson)
  poetry run python scripts/nvd_ingest.py load --curated-in data/nvd/curated/2024-01.ndjson

  # One-shot (memory): fetch + transform + Snowflake (small windows)
  poetry run python scripts/nvd_ingest.py sync --start 2024-01-01 --end 2024-01-02
  poetry run python scripts/nvd_ingest.py sync --cve CVE-2024-21413 --dry-run

NVD_API_KEY in .env: ~0.65s between paginated requests; without key ~6s.
Optional NVD_MIN_REQUEST_INTERVAL_SEC overrides both.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def _display_out_path(p: str) -> str:
    from ingestion.nvd.s3_io import is_s3_uri

    if is_s3_uri(p):
        return p
    return str(Path(p).resolve())


def _parse_date(s: str) -> date:
    return date.fromisoformat(s)


def _resolve_key(explicit: str | None) -> str | None:
    k = (explicit or "").strip() or None
    if k:
        return k
    from app.config import get_settings

    return (get_settings().nvd_api_key or "").strip() or None


def main() -> int:
    parser = argparse.ArgumentParser(description="NVD ingest: fetch / transform / load / sync.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_fetch = sub.add_parser("fetch", help="Download NVD to raw NDJSON")
    p_fetch.add_argument("--start", type=str, default=None)
    p_fetch.add_argument("--end", type=str, default=None)
    p_fetch.add_argument("--cve", type=str, default=None)
    p_fetch.add_argument(
        "--raw-out",
        type=str,
        required=True,
        help="Output path for raw vulnerability NDJSON",
    )
    p_fetch.add_argument("--api-key", type=str, default=None)

    p_transform = sub.add_parser("transform", help="Raw NDJSON -> curated NDJSON")
    p_transform.add_argument("--raw-in", type=str, required=True)
    p_transform.add_argument("--curated-out", type=str, required=True)

    p_load = sub.add_parser("load", help="Curated NDJSON -> Snowflake cve_records")
    p_load.add_argument("--curated-in", type=str, required=True)
    p_load.add_argument("--batch-size", type=int, default=200)

    p_sync = sub.add_parser("sync", help="Fetch in memory, transform, upsert (or --dry-run)")
    p_sync.add_argument("--start", type=str, default=None)
    p_sync.add_argument("--end", type=str, default=None)
    p_sync.add_argument("--cve", type=str, default=None)
    p_sync.add_argument("--dry-run", action="store_true")
    p_sync.add_argument("--api-key", type=str, default=None)

    args = parser.parse_args()

    if args.command == "fetch":
        has_range = bool(args.start and args.end)
        has_cve = bool(args.cve)
        if has_range == has_cve:
            print("fetch: provide --cve or both --start and --end.", file=sys.stderr)
            return 1
        from ingestion.nvd.pipeline import (
            fetch_cve_to_raw_file,
            fetch_delta_to_raw_file,
        )

        key = _resolve_key(args.api_key)
        if has_cve:
            stats = fetch_cve_to_raw_file(args.cve.upper(), args.raw_out, key)
        else:
            stats = fetch_delta_to_raw_file(
                _parse_date(args.start), _parse_date(args.end), args.raw_out, key
            )
        n = stats.get("fetched", stats.get("written", 0))
        print(f"fetched_lines={n} pages={stats.get('pages', 1)}")
        print(f"raw_out={_display_out_path(args.raw_out)}")
        return 0

    if args.command == "transform":
        from ingestion.nvd.pipeline import transform_raw_file_to_curated

        stats = transform_raw_file_to_curated(args.raw_in, args.curated_out)
        print(
            f"lines_in={stats['lines_in']} transformed={stats['transformed']} "
            f"skipped={stats['skipped']}"
        )
        print(f"curated_out={_display_out_path(args.curated_out)}")
        return 0

    if args.command == "load":
        from ingestion.nvd.pipeline import load_curated_file_to_snowflake

        stats = load_curated_file_to_snowflake(args.curated_in, batch_size=args.batch_size)
        print(
            f"lines_read={stats['lines_read']} rows_upserted={stats['rows_upserted']} "
            f"mappings_upserted={stats.get('mappings_upserted', 0)} batches={stats['batches']}"
        )
        print(f"curated_in={_display_out_path(args.curated_in)}")
        return 0

    if args.command == "sync":
        has_range = bool(args.start and args.end)
        has_cve = bool(args.cve)
        if has_range == has_cve:
            print("sync: provide --cve or both --start and --end.", file=sys.stderr)
            return 1
        key = _resolve_key(args.api_key)

        if args.dry_run:
            from ingestion.nvd.client import fetch_nvd_delta, fetch_single_cve
            from ingestion.nvd.transform import transform_vulnerability

            if has_cve:
                raw = fetch_single_cve(args.cve.upper(), key)
                items = [raw] if raw else []
            else:
                items = fetch_nvd_delta(_parse_date(args.start), _parse_date(args.end), key)
            ok = 0
            for item in items:
                try:
                    rec = transform_vulnerability(item)
                    ok += 1
                    if ok == 1:
                        print("sample keys:", sorted(rec.keys()))
                        print("sample cve_id:", rec.get("cve_id"))
                except (KeyError, ValueError, TypeError) as e:
                    print(f"skip transform error: {e}", file=sys.stderr)
            print(f"dry-run: fetched {len(items)}, transformed {ok}")
            return 0

        from ingestion.nvd.pipeline import sync_delta, sync_single_cve

        if has_cve:
            stats = sync_single_cve(args.cve.upper(), key)
        else:
            stats = sync_delta(_parse_date(args.start), _parse_date(args.end), key)
        print(
            f"fetched={stats['fetched']} transformed={stats['transformed']} "
            f"upserted={stats['upserted']}"
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
