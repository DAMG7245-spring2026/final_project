"""
Backfill / refresh `document_type` for every row in ADVISORIES.

Strategy:
  - Classify from (title, advisory_type, co_authors) first.
  - For ambiguous rows (would-be CSA with < 2 co_authors), download the raw HTML
    from S3 and re-run with body fingerprinting to catch joint CSAs that
    `_extract_co_authors` missed.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from time import perf_counter
from typing import Any
from uuid import uuid4

from ingestion.advisory.html_parser import (
    IR_LESSONS_RE,
    STOPRANSOMWARE_RE,
    _classify_document_type,
    _clean_html,
)

logger = logging.getLogger(__name__)


def _get_snowflake_service():
    from app.services.snowflake import get_snowflake_service

    return get_snowflake_service()


def _get_s3_storage():
    from app.services.s3_storage import get_s3_storage

    return get_s3_storage()


def _parse_co_authors(raw: Any) -> list[str]:
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


def run_backfill_document_type(write: bool = False) -> dict[str, Any]:
    """
    Re-classify `document_type` for all rows in `advisories`.

    Args:
        write: If True, UPDATE Snowflake rows. Default False (dry-run).

    Returns:
        Stats dict with run_id, processed, downloaded_html, distribution,
        rescued_joint_csa, updated, elapsed_sec.
    """
    run_id = uuid4().hex[:12]
    started = perf_counter()

    sf = _get_snowflake_service()
    s3 = _get_s3_storage()
    bucket = s3.bucket

    with sf.cursor() as cur:
        cur.execute(
            "SELECT advisory_id, s3_raw_path, title, advisory_type, co_authors "
            "FROM advisories"
        )
        rows = cur.fetchall()

    logger.info("advisory_classify_start run_id=%s total=%s", run_id, len(rows))

    counter: Counter[str] = Counter()
    rescued_joint_csa: list[tuple[str, str]] = []
    updates: list[tuple[str, str]] = []
    downloaded = 0

    for i, (advisory_id, s3_path, title, advisory_type, co_authors_raw) in enumerate(rows, 1):
        co_authors = _parse_co_authors(co_authors_raw)

        main_soup = None
        if _needs_html_lookup(title, advisory_type, co_authors) and s3_path:
            try:
                obj = s3.client.get_object(Bucket=bucket, Key=s3_path)
                html = obj["Body"].read().decode("utf-8", errors="replace")
                main_soup = _clean_html(html)
                downloaded += 1
            except Exception as exc:
                logger.warning(
                    "advisory_classify_s3_fail advisory_id=%s error=%s", advisory_id, exc
                )

        dt = _classify_document_type(
            title or "",
            advisory_type or "",
            co_authors,
            main_soup=main_soup,
        )
        counter[dt] += 1
        updates.append((dt, advisory_id))

        if main_soup is not None and dt == "JOINT_CSA":
            rescued_joint_csa.append((advisory_id, (title or "")[:90]))

        if i % 50 == 0:
            logger.info(
                "advisory_classify_progress run_id=%s %s/%s downloaded=%s",
                run_id, i, len(rows), downloaded,
            )

    updated = 0
    if write and updates:
        with sf.cursor() as cur:
            for dt, aid in updates:
                cur.execute(
                    "UPDATE advisories SET document_type = %s WHERE advisory_id = %s",
                    (dt, aid),
                )
            updated = len(updates)

    elapsed = perf_counter() - started
    distribution = dict(counter.most_common())
    logger.info(
        "advisory_classify_summary run_id=%s processed=%s downloaded=%s updated=%s "
        "rescued_joint_csa=%s distribution=%s elapsed_sec=%.3f",
        run_id, len(rows), downloaded, updated, len(rescued_joint_csa),
        distribution, elapsed,
    )

    return {
        "run_id": run_id,
        "processed": len(rows),
        "downloaded_html": downloaded,
        "distribution": distribution,
        "rescued_joint_csa": [aid for aid, _ in rescued_joint_csa],
        "updated": updated,
        "dry_run": not write,
        "elapsed_sec": elapsed,
    }
