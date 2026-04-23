"""
Chunk advisories with chunker_v2 and write rows to ADVISORY_CHUNKS.

For each advisory:
  1. Fetch raw HTML from S3.
  2. Run `chunk_advisory(advisory_id, document_type, html)`.
  3. DELETE existing chunks for that advisory, INSERT fresh v2 chunks.

NOTE: `chunk_embedding` is NOT preserved — callers must re-run
`ingestion.advisory.embedder.run_embed_chunks` afterwards.
"""

from __future__ import annotations

import json
import logging
from time import perf_counter
from typing import Any
from uuid import uuid4

from ingestion.advisory.chunker_v2 import chunk_advisory

logger = logging.getLogger(__name__)


INSERT_SQL = """
    INSERT INTO advisory_chunks
        (chunk_id, advisory_id, chunk_index, section_name, sub_section,
         chunk_text, token_count, content_hash,
         cve_ids, cwe_ids, mitre_tech_ids)
    SELECT %s, %s, %s, %s, %s,
           %s, %s, %s,
           PARSE_JSON(%s)::ARRAY,
           PARSE_JSON(%s)::ARRAY,
           PARSE_JSON(%s)::ARRAY
"""


def _get_snowflake_service():
    from app.services.snowflake import get_snowflake_service

    return get_snowflake_service()


def _get_s3_storage():
    from app.services.s3_storage import get_s3_storage

    return get_s3_storage()


def _fetch_html(s3_client: Any, bucket: str, s3_path: str) -> str:
    obj = s3_client.get_object(Bucket=bucket, Key=s3_path)
    return obj["Body"].read().decode("utf-8", errors="replace")


def _insert_chunks(cur: Any, chunks: list[Any]) -> None:
    for c in chunks:
        sub = c.sub_section
        if sub and len(sub) > 200:
            sub = sub[:200]
        cur.execute(INSERT_SQL, (
            c.chunk_id, c.advisory_id, c.chunk_index, c.section_name, sub,
            c.chunk_text, c.token_count, c.content_hash,
            json.dumps(c.cve_ids), json.dumps(c.cwe_ids), json.dumps(c.mitre_tech_ids),
        ))


def run_chunk_advisory(advisory_id: str, commit: bool = False) -> dict[str, Any]:
    """
    Re-chunk a single advisory.

    Args:
        advisory_id: target advisory.
        commit: If True, DELETE + INSERT in Snowflake. Default False (dry-run).

    Returns:
        {advisory_id, document_type, new_chunks, deleted, inserted, dry_run, elapsed_sec}
    """
    started = perf_counter()
    sf = _get_snowflake_service()
    s3 = _get_s3_storage()
    bucket = s3.bucket

    with sf.cursor() as cur:
        cur.execute(
            "SELECT advisory_id, document_type, s3_raw_path, title "
            "FROM advisories WHERE advisory_id = %s",
            (advisory_id,),
        )
        row = cur.fetchone()

    if not row:
        raise ValueError(f"advisory not found: {advisory_id}")

    advisory_id, document_type, s3_path, title = row
    logger.info(
        "advisory_chunk_one start advisory_id=%s document_type=%s s3=%s",
        advisory_id, document_type, s3_path,
    )

    html = _fetch_html(s3.client, bucket, s3_path)
    chunks = chunk_advisory(advisory_id, document_type, html)
    if not chunks:
        raise RuntimeError(f"zero chunks produced for {advisory_id}")

    deleted = 0
    inserted = 0
    if commit:
        with sf.cursor() as cur:
            cur.execute(
                "DELETE FROM advisory_chunks WHERE advisory_id = %s",
                (advisory_id,),
            )
            deleted = cur.rowcount
            _insert_chunks(cur, chunks)
            inserted = len(chunks)

    elapsed = perf_counter() - started
    logger.info(
        "advisory_chunk_one summary advisory_id=%s new_chunks=%s deleted=%s inserted=%s "
        "dry_run=%s elapsed_sec=%.3f",
        advisory_id, len(chunks), deleted, inserted, not commit, elapsed,
    )

    return {
        "advisory_id": advisory_id,
        "document_type": document_type,
        "title": title,
        "new_chunks": len(chunks),
        "deleted": deleted,
        "inserted": inserted,
        "dry_run": not commit,
        "elapsed_sec": elapsed,
    }


def run_chunk_all(
    only_type: str | None = None,
    limit: int | None = None,
    commit: bool = False,
    advisory_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Bulk re-chunk advisories with s3_raw_path + document_type set.

    Stops immediately on the first error (no skip-and-continue).

    Args:
        only_type: optional document_type filter.
        limit: optional cap for debugging.
        commit: If True, DELETE + INSERT. Default False (dry-run).
        advisory_ids: optional whitelist. When None → chunk everything (full refresh).
            When [] → process nothing (fast no-op, used by DAG when scraper
            found no new advisories). When non-empty → chunk only those rows.

    Returns:
        {run_id, processed, chunked, deleted, inserted, failed_advisory_id,
         dry_run, elapsed_sec}
    """
    run_id = uuid4().hex[:12]
    started = perf_counter()

    if advisory_ids is not None and not advisory_ids:
        logger.info("advisory_chunk_all_skip run_id=%s reason=empty_advisory_ids", run_id)
        return {
            "run_id": run_id,
            "processed": 0,
            "chunked": 0,
            "deleted": 0,
            "inserted": 0,
            "failed_advisory_id": None,
            "dry_run": not commit,
            "elapsed_sec": perf_counter() - started,
        }

    sf = _get_snowflake_service()
    s3 = _get_s3_storage()
    bucket = s3.bucket

    sql = (
        "SELECT advisory_id, document_type, s3_raw_path, title "
        "FROM advisories "
        "WHERE s3_raw_path IS NOT NULL AND document_type IS NOT NULL"
    )
    params: list[Any] = []
    if only_type:
        sql += " AND document_type = %s"
        params.append(only_type)
    if advisory_ids:
        placeholders = ",".join(["%s"] * len(advisory_ids))
        sql += f" AND advisory_id IN ({placeholders})"
        params.extend(advisory_ids)
    sql += " ORDER BY document_type, published_date DESC NULLS LAST"

    with sf.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    if limit:
        rows = rows[:limit]

    logger.info(
        "advisory_chunk_all_start run_id=%s total=%s only_type=%s "
        "advisory_ids_filter=%s dry_run=%s",
        run_id, len(rows), only_type,
        len(advisory_ids) if advisory_ids else None, not commit,
    )

    total_chunked = 0
    total_deleted = 0
    total_inserted = 0
    failed_advisory_id: str | None = None

    for i, (advisory_id, document_type, s3_path, title) in enumerate(rows, 1):
        try:
            html = _fetch_html(s3.client, bucket, s3_path)
            chunks = chunk_advisory(advisory_id, document_type, html)
            if not chunks:
                raise RuntimeError(f"zero chunks produced for {advisory_id}")

            max_tok = max(c.token_count for c in chunks)
            total_chunked += len(chunks)
            logger.info(
                "advisory_chunk_all_item run_id=%s [%s/%s] advisory_id=%s "
                "document_type=%s chunks=%s max_tokens=%s title=%s",
                run_id, i, len(rows), advisory_id, document_type,
                len(chunks), max_tok, (title or "")[:60],
            )

            if not commit:
                continue

            with sf.cursor() as cur:
                cur.execute(
                    "DELETE FROM advisory_chunks WHERE advisory_id = %s",
                    (advisory_id,),
                )
                total_deleted += cur.rowcount
                _insert_chunks(cur, chunks)
                total_inserted += len(chunks)

        except Exception as exc:
            failed_advisory_id = advisory_id
            logger.error(
                "advisory_chunk_all_fail run_id=%s advisory_id=%s error=%s "
                "processed=%s deleted=%s inserted=%s",
                run_id, advisory_id, exc, i - 1, total_deleted, total_inserted,
            )
            raise

    elapsed = perf_counter() - started
    logger.info(
        "advisory_chunk_all_summary run_id=%s processed=%s chunked=%s deleted=%s "
        "inserted=%s dry_run=%s elapsed_sec=%.3f",
        run_id, len(rows), total_chunked, total_deleted, total_inserted,
        not commit, elapsed,
    )

    return {
        "run_id": run_id,
        "processed": len(rows),
        "chunked": total_chunked,
        "deleted": total_deleted,
        "inserted": total_inserted,
        "failed_advisory_id": failed_advisory_id,
        "dry_run": not commit,
        "elapsed_sec": elapsed,
    }
