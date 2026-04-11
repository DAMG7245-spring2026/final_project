"""
Backfill `document_type` for every row in the ADVISORIES table.

Strategy:
  - Always classify using (title, advisory_type, co_authors) first.
  - For ambiguous cases (would-be CSA with < 2 co_authors) download the raw
    HTML from S3 and re-run with body fingerprinting to catch joint CSAs
    that _extract_co_authors missed.

Default is dry-run (no writes). Pass --write to commit updates.
"""
import argparse
import json
import os
from collections import Counter, defaultdict

from dotenv import load_dotenv

load_dotenv()

import boto3
import snowflake.connector

from app.config import get_settings
from ingestion.advisory.html_parser import (
    IR_LESSONS_RE,
    STOPRANSOMWARE_RE,
    _classify_document_type,
    _clean_html,
)


def _parse_co_authors(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return []


def _needs_html_lookup(title: str, advisory_type: str, co_authors: list[str]) -> bool:
    """True iff title/co_authors alone can't confidently classify — only then do we hit S3."""
    if advisory_type == "analysis_report":
        return False
    t = title or ""
    if STOPRANSOMWARE_RE.search(t):
        return False
    if IR_LESSONS_RE.search(t):
        return False
    if len(co_authors) >= 2:
        return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Commit UPDATEs (default: dry-run)")
    args = parser.parse_args()

    s = get_settings()

    conn = snowflake.connector.connect(
        account=s.snowflake_account,
        user=s.snowflake_user,
        password=s.snowflake_password,
        database=s.snowflake_database,
        schema=s.snowflake_schema,
        warehouse=s.snowflake_warehouse,
    )
    s3 = boto3.client(
        "s3",
        aws_access_key_id=s.aws_access_key_id,
        aws_secret_access_key=s.aws_secret_access_key,
        region_name=s.aws_region,
    )

    cur = conn.cursor()
    cur.execute(
        "SELECT advisory_id, s3_raw_path, title, advisory_type, co_authors FROM advisories"
    )
    rows = cur.fetchall()
    print(f"Loaded {len(rows)} advisories")

    counter = Counter()
    changed_from_csa = []
    updates: list[tuple[str, str]] = []
    downloaded = 0

    for i, (advisory_id, s3_path, title, advisory_type, co_authors_raw) in enumerate(rows, 1):
        co_authors = _parse_co_authors(co_authors_raw)

        main_soup = None
        if _needs_html_lookup(title, advisory_type, co_authors) and s3_path:
            try:
                obj = s3.get_object(Bucket=s.s3_bucket, Key=s3_path)
                html = obj["Body"].read().decode("utf-8", errors="replace")
                main_soup = _clean_html(html)
                downloaded += 1
            except Exception as e:
                print(f"  warn: S3 download failed for {advisory_id}: {e}")

        dt = _classify_document_type(
            title or "",
            advisory_type or "",
            co_authors,
            main_soup=main_soup,
        )
        counter[dt] += 1
        updates.append((dt, advisory_id))

        if main_soup is not None and dt == "JOINT_CSA":
            changed_from_csa.append((advisory_id, (title or "")[:90]))

        if i % 50 == 0:
            print(f"  progress {i}/{len(rows)}  (downloaded={downloaded})")

    print(f"\nDownloaded {downloaded} HTML files from S3")
    print("\nFinal distribution:")
    for dt, n in counter.most_common():
        print(f"  {dt:16s} {n}")

    if changed_from_csa:
        print(f"\nBody fallback rescued {len(changed_from_csa)} rows as JOINT_CSA (samples):")
        for aid, t in changed_from_csa[:10]:
            print(f"  {aid}  {t}")

    if not args.write:
        print("\n[dry-run] No rows updated. Rerun with --write to commit.")
        return

    print(f"\nUpdating {len(updates)} rows...")
    for dt, aid in updates:
        cur.execute(
            "UPDATE advisories SET document_type = %s WHERE advisory_id = %s",
            (dt, aid),
        )
    conn.commit()
    print("Done.")


if __name__ == "__main__":
    main()
