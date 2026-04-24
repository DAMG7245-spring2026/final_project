"""Insert/update PUBLIC.pipeline_runs for Airflow and scripts."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


def _now_ntz() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def start_pipeline_run(
    *,
    dag_id: str | None = None,
    source: str | None = None,
    logical_source: str | None = None,
    airflow_dag_run_id: str | None = None,
    airflow_task_id: str | None = None,
    watermark_from: datetime | None = None,
    watermark_to: datetime | None = None,
) -> str:
    """Insert a running row; returns run_id (primary key)."""
    from app.services.snowflake import get_snowflake_service

    run_id = uuid4().hex[:32]
    started = _now_ntz()
    sf = get_snowflake_service()
    sf.execute_write(
        """
        INSERT INTO pipeline_runs (
            run_id,
            dag_id,
            source,
            logical_source,
            airflow_dag_run_id,
            airflow_task_id,
            records_fetched,
            records_new,
            records_rejected,
            llm_calls_made,
            cache_hits,
            started_at,
            completed_at,
            status,
            error_message,
            watermark_from,
            watermark_to
        ) VALUES (
            %s, %s, %s, %s, %s, %s,
            NULL, NULL, NULL, NULL, NULL,
            %s, NULL, %s, NULL, %s, %s
        )
        """,
        (
            run_id,
            dag_id,
            source,
            logical_source,
            airflow_dag_run_id,
            airflow_task_id,
            started,
            "running",
            watermark_from,
            watermark_to,
        ),
    )
    return run_id


def complete_pipeline_run(
    run_id: str,
    *,
    status: str,
    error_message: str | None = None,
    stats: dict[str, Any] | None = None,
    records_fetched: int | None = None,
    records_new: int | None = None,
    records_rejected: int | None = None,
) -> None:
    """Set completed_at, status, optional error and stats VARIANT."""
    from app.services.snowflake import get_snowflake_service

    stats_json: str | None = json.dumps(stats) if stats is not None else None
    completed = _now_ntz()
    sf = get_snowflake_service()
    if stats_json is not None:
        sf.execute_write(
            """
            UPDATE pipeline_runs
            SET
                completed_at = %s,
                status = %s,
                error_message = %s,
                stats = TRY_PARSE_JSON(%s),
                records_fetched = COALESCE(%s, records_fetched),
                records_new = COALESCE(%s, records_new),
                records_rejected = COALESCE(%s, records_rejected)
            WHERE run_id = %s
            """,
            (
                completed,
                status[:20],
                error_message,
                stats_json,
                records_fetched,
                records_new,
                records_rejected,
                run_id,
            ),
        )
    else:
        sf.execute_write(
            """
            UPDATE pipeline_runs
            SET
                completed_at = %s,
                status = %s,
                error_message = %s,
                records_fetched = COALESCE(%s, records_fetched),
                records_new = COALESCE(%s, records_new),
                records_rejected = COALESCE(%s, records_rejected)
            WHERE run_id = %s
            """,
            (
                completed,
                status[:20],
                error_message,
                records_fetched,
                records_new,
                records_rejected,
                run_id,
            ),
        )


def log_pipeline_run_swallow_errors(
    *,
    dag_id: str | None,
    source: str | None,
    logical_source: str | None,
    airflow_dag_run_id: str | None,
    airflow_task_id: str | None,
    status: str,
    stats: dict[str, Any] | None = None,
    error_message: str | None = None,
) -> None:
    """One-shot insert completed row (for simple tasks). Never raises."""
    try:
        rid = start_pipeline_run(
            dag_id=dag_id,
            source=source,
            logical_source=logical_source,
            airflow_dag_run_id=airflow_dag_run_id,
            airflow_task_id=airflow_task_id,
        )
        complete_pipeline_run(
            rid,
            status=status,
            error_message=error_message,
            stats=stats,
        )
    except Exception as exc:  # pragma: no cover - best-effort audit
        logger.warning("pipeline_runs log failed: %s", exc)
