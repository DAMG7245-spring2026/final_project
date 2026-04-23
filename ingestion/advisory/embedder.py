"""
Compute Snowflake Cortex embeddings for advisory chunks and full reports.

Model: snowflake-arctic-embed-l-v2.0 (1024-dim, 8192-token context).
Everything runs server-side — chunk_text never leaves Snowflake.
"""

from __future__ import annotations

import logging
from time import perf_counter
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


EMBED_MODEL = "snowflake-arctic-embed-l-v2.0"
DEFAULT_CHUNK_BATCH = 200
DEFAULT_REPORT_BATCH = 20


def _get_snowflake_service():
    from app.services.snowflake import get_snowflake_service

    return get_snowflake_service()


def run_embed_chunks(
    advisory_id: str | None = None,
    force: bool = False,
    batch_size: int = DEFAULT_CHUNK_BATCH,
    limit: int | None = None,
    write: bool = False,
) -> dict[str, Any]:
    """
    Backfill `advisory_chunks.chunk_embedding` via Snowflake Cortex.

    Args:
        advisory_id: only embed chunks for this advisory (optional).
        force: re-embed rows that already have an embedding.
        batch_size: chunks per Cortex UPDATE call.
        limit: cap number of chunks (for testing).
        write: If True, commit UPDATEs. Default False (dry-run).

    Returns:
        {run_id, target, embedded, with_embeddings_after, dry_run, elapsed_sec}
    """
    run_id = uuid4().hex[:12]
    started = perf_counter()
    sf = _get_snowflake_service()

    where = []
    params: list[Any] = []
    if not force:
        where.append("chunk_embedding IS NULL")
    if advisory_id:
        where.append("advisory_id = %s")
        params.append(advisory_id)
    where.append("chunk_text IS NOT NULL")
    where_sql = " AND ".join(where)

    with sf.cursor() as cur:
        cur.execute(
            f"SELECT COUNT(*), COALESCE(MAX(token_count),0), COALESCE(AVG(token_count),0)::INT "
            f"FROM advisory_chunks WHERE {where_sql}",
            params,
        )
        total, max_tok, avg_tok = cur.fetchone()
        if limit:
            total = min(total, limit)

        logger.info(
            "advisory_embed_chunks_start run_id=%s target=%s max_tokens=%s avg_tokens=%s "
            "model=%s dry_run=%s",
            run_id, total, max_tok, avg_tok, EMBED_MODEL, not write,
        )

        if total == 0:
            elapsed = perf_counter() - started
            return {
                "run_id": run_id,
                "target": 0,
                "embedded": 0,
                "with_embeddings_after": 0,
                "dry_run": not write,
                "elapsed_sec": elapsed,
            }

        limit_sql = f" LIMIT {limit}" if limit else ""
        cur.execute(
            f"SELECT chunk_id FROM advisory_chunks WHERE {where_sql} "
            f"ORDER BY chunk_id{limit_sql}",
            params,
        )
        chunk_ids = [row[0] for row in cur.fetchall()]

        if not write:
            elapsed = perf_counter() - started
            logger.info(
                "advisory_embed_chunks_dry_run run_id=%s would_embed=%s",
                run_id, len(chunk_ids),
            )
            return {
                "run_id": run_id,
                "target": len(chunk_ids),
                "embedded": 0,
                "with_embeddings_after": 0,
                "dry_run": True,
                "elapsed_sec": elapsed,
            }

        done = 0
        batch_start = perf_counter()
        for i in range(0, len(chunk_ids), batch_size):
            batch = chunk_ids[i : i + batch_size]
            placeholders = ",".join(["%s"] * len(batch))
            sql = (
                "UPDATE advisory_chunks "
                "SET chunk_embedding = SNOWFLAKE.CORTEX.EMBED_TEXT_1024(%s, chunk_text) "
                f"WHERE chunk_id IN ({placeholders})"
            )
            cur.execute(sql, [EMBED_MODEL, *batch])
            done += len(batch)
            elapsed_batch = perf_counter() - batch_start
            rate = done / elapsed_batch if elapsed_batch else 0
            logger.info(
                "advisory_embed_chunks_progress run_id=%s %s/%s rate=%.1f/s",
                run_id, done, len(chunk_ids), rate,
            )

        cur.execute(
            "SELECT COUNT(*) FROM advisory_chunks WHERE chunk_embedding IS NOT NULL"
        )
        (with_emb,) = cur.fetchone()

    elapsed = perf_counter() - started
    logger.info(
        "advisory_embed_chunks_summary run_id=%s embedded=%s with_embeddings_after=%s "
        "elapsed_sec=%.3f",
        run_id, done, with_emb, elapsed,
    )

    return {
        "run_id": run_id,
        "target": len(chunk_ids),
        "embedded": done,
        "with_embeddings_after": with_emb,
        "dry_run": False,
        "elapsed_sec": elapsed,
    }


def run_embed_reports(
    force: bool = False,
    batch_size: int = DEFAULT_REPORT_BATCH,
    write: bool = False,
) -> dict[str, Any]:
    """
    Backfill `advisories.report_embedding` via Snowflake Cortex.

    Chunks are LISTAGG'd server-side in chunk_index order, then embedded. Reports
    longer than 8192 tokens are truncated by Cortex.

    Args:
        force: re-embed rows that already have an embedding.
        batch_size: advisories per Cortex UPDATE call.
        write: If True, commit UPDATEs. Default False (dry-run).

    Returns:
        {run_id, target, embedded, with_embeddings_after, dry_run, elapsed_sec}
    """
    run_id = uuid4().hex[:12]
    started = perf_counter()
    sf = _get_snowflake_service()

    where = "EXISTS (SELECT 1 FROM advisory_chunks c WHERE c.advisory_id = a.advisory_id)"
    if not force:
        where += " AND a.report_embedding IS NULL"

    with sf.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM advisories a WHERE {where}")
        total = cur.fetchone()[0]
        logger.info(
            "advisory_embed_reports_start run_id=%s target=%s model=%s batch=%s dry_run=%s",
            run_id, total, EMBED_MODEL, batch_size, not write,
        )

        if total == 0:
            elapsed = perf_counter() - started
            return {
                "run_id": run_id,
                "target": 0,
                "embedded": 0,
                "with_embeddings_after": 0,
                "dry_run": not write,
                "elapsed_sec": elapsed,
            }

        cur.execute(f"SELECT advisory_id FROM advisories a WHERE {where} ORDER BY advisory_id")
        advisory_ids = [row[0] for row in cur.fetchall()]

        if not write:
            elapsed = perf_counter() - started
            logger.info(
                "advisory_embed_reports_dry_run run_id=%s would_embed=%s",
                run_id, len(advisory_ids),
            )
            return {
                "run_id": run_id,
                "target": len(advisory_ids),
                "embedded": 0,
                "with_embeddings_after": 0,
                "dry_run": True,
                "elapsed_sec": elapsed,
            }

        done = 0
        batch_start = perf_counter()
        for i in range(0, len(advisory_ids), batch_size):
            batch = advisory_ids[i : i + batch_size]
            placeholders = ",".join(["%s"] * len(batch))
            sql = f"""
                UPDATE advisories a
                SET report_embedding = SNOWFLAKE.CORTEX.EMBED_TEXT_1024(
                    %s,
                    (
                        SELECT LISTAGG(c.chunk_text, '\n\n') WITHIN GROUP (ORDER BY c.chunk_index)
                        FROM advisory_chunks c
                        WHERE c.advisory_id = a.advisory_id
                    )
                )
                WHERE a.advisory_id IN ({placeholders})
            """
            cur.execute(sql, [EMBED_MODEL, *batch])
            done += len(batch)
            elapsed_batch = perf_counter() - batch_start
            rate = done / elapsed_batch if elapsed_batch else 0
            logger.info(
                "advisory_embed_reports_progress run_id=%s %s/%s rate=%.1f/s",
                run_id, done, len(advisory_ids), rate,
            )

        cur.execute("SELECT COUNT(*) FROM advisories WHERE report_embedding IS NOT NULL")
        with_emb = cur.fetchone()[0]

    elapsed = perf_counter() - started
    logger.info(
        "advisory_embed_reports_summary run_id=%s embedded=%s with_embeddings_after=%s "
        "elapsed_sec=%.3f",
        run_id, done, with_emb, elapsed,
    )

    return {
        "run_id": run_id,
        "target": len(advisory_ids),
        "embedded": done,
        "with_embeddings_after": with_emb,
        "dry_run": False,
        "elapsed_sec": elapsed,
    }
