"""Ingestion high-water marks in Snowflake PUBLIC.ingestion_checkpoints."""

from __future__ import annotations

import json
from datetime import date, timedelta
from typing import Any

NVD_INCREMENTAL_SOURCE = "nvd_api_last_modified_through"
NVD_S3_SLICE_SOURCE = "nvd_s3_slice_pipeline_through"

_CHECKPOINTS_SETUP_HINT = (
    "Snowflake table PUBLIC.ingestion_checkpoints is missing or this user cannot access it. "
    "Run snowflake/sql/07_ingestion_monitoring.sql in your CTI database (same DB/schema as "
    "SNOWFLAKE_* in Airflow .env), then grant the Airflow Snowflake role SELECT and MERGE on "
    "ingestion_checkpoints (and pipeline_runs for run audit rows). See README prerequisites "
    "for nvd_incremental_dag / nvd_s3_slice_pipeline_dag."
)


def _reraise_if_checkpoint_table_missing(exc: BaseException) -> None:
    """Turn Snowflake 42S02 / access errors on ingestion_checkpoints into an actionable message."""
    text = str(exc).lower()
    if "ingestion_checkpoints" not in text:
        raise exc
    if any(
        s in text
        for s in (
            "does not exist",
            "not authorized",
            "42s02",
            "002003",
        )
    ):
        raise RuntimeError(_CHECKPOINTS_SETUP_HINT) from exc
    raise exc


def get_checkpoint(source: str) -> dict[str, Any] | None:
    from app.services.snowflake import get_snowflake_service

    try:
        return get_snowflake_service().execute_one(
            """
            SELECT source, watermark_ts, watermark_date, updated_at, last_run_id, notes
            FROM ingestion_checkpoints
            WHERE source = %s
            """,
            (source,),
        )
    except Exception as exc:
        _reraise_if_checkpoint_table_missing(exc)


def upsert_checkpoint(
    source: str,
    *,
    watermark_ts: Any | None = None,
    watermark_date: date | None = None,
    last_run_id: str | None = None,
    notes: dict[str, Any] | None = None,
) -> None:
    from app.services.snowflake import get_snowflake_service

    notes_json = json.dumps(notes) if notes is not None else None
    try:
        get_snowflake_service().execute_write(
            """
            MERGE INTO ingestion_checkpoints AS t
            USING (
                SELECT
                    %s AS source,
                    %s::TIMESTAMP_NTZ AS watermark_ts,
                    %s::DATE AS watermark_date,
                    %s AS last_run_id,
                    TRY_PARSE_JSON(%s) AS notes
            ) AS s
            ON t.source = s.source
            WHEN MATCHED THEN UPDATE SET
                watermark_ts = COALESCE(s.watermark_ts, t.watermark_ts),
                watermark_date = COALESCE(s.watermark_date, t.watermark_date),
                updated_at = CURRENT_TIMESTAMP(),
                last_run_id = COALESCE(s.last_run_id, t.last_run_id),
                notes = COALESCE(s.notes, t.notes)
            WHEN NOT MATCHED THEN INSERT (source, watermark_ts, watermark_date, last_run_id, notes)
            VALUES (s.source, s.watermark_ts, s.watermark_date, s.last_run_id, s.notes)
            """,
            (source, watermark_ts, watermark_date, last_run_id, notes_json),
        )
    except Exception as exc:
        _reraise_if_checkpoint_table_missing(exc)


def _cold_start_nvd_start() -> date:
    """MAX(last_modified) date from cve_records, else a safe floor."""
    from app.services.snowflake import get_snowflake_service

    row = get_snowflake_service().execute_one(
        "SELECT MAX(last_modified) AS mx FROM cve_records"
    )
    mx = row.get("mx") if row else None
    if mx is None:
        return date(2000, 1, 1)
    if hasattr(mx, "date"):
        return mx.date()
    # string from Snowflake sometimes
    s = str(mx)[:10]
    try:
        return date.fromisoformat(s)
    except ValueError:
        return date(2000, 1, 1)


def resolve_nvd_date_window(
    conf: dict[str, Any] | None,
    *,
    today_utc: date | None = None,
    checkpoint_source: str = NVD_INCREMENTAL_SOURCE,
) -> tuple[date, date]:
    """
    Return (start_date, end_date) inclusive for NVD incremental sync.

    Resolution: conf force_start/force_end → checkpoint + 1 day → cold start MAX.
    end_date defaults to today_utc (UTC calendar date).

    ``checkpoint_source`` selects which ``ingestion_checkpoints`` row to use
    (e.g. :data:`NVD_INCREMENTAL_SOURCE` vs :data:`NVD_S3_SLICE_SOURCE`).
    """
    conf = conf or {}
    today = today_utc or date.today()

    fs = conf.get("force_start") or conf.get("start_date")
    fe = conf.get("force_end") or conf.get("end_date")
    if fs:
        start = date.fromisoformat(str(fs)[:10])
        end = date.fromisoformat(str(fe)[:10]) if fe else today
        if end < start:
            end = start
        return start, end

    cp = get_checkpoint(checkpoint_source)
    if cp and cp.get("watermark_date") is not None:
        wd = cp["watermark_date"]
        if hasattr(wd, "date"):
            wd = wd.date()
        elif isinstance(wd, str):
            wd = date.fromisoformat(wd[:10])
        start = wd + timedelta(days=1)
    else:
        start = _cold_start_nvd_start()

    end = today
    if end < start:
        end = start
    return start, end


def resolve_nvd_s3_slice_window(
    conf: dict[str, Any] | None,
    *,
    today_utc: date | None = None,
) -> tuple[date, date]:
    """Same as :func:`resolve_nvd_date_window` but uses :data:`NVD_S3_SLICE_SOURCE` checkpoint."""
    return resolve_nvd_date_window(conf, today_utc=today_utc, checkpoint_source=NVD_S3_SLICE_SOURCE)


def slice_date_range(start: date, end: date, *, max_days: int = 7) -> list[tuple[date, date]]:
    """Split [start, end] into inclusive chunks of at most max_days each."""
    if max_days < 1:
        max_days = 1
    out: list[tuple[date, date]] = []
    cur = start
    while cur <= end:
        chunk_end = min(cur + timedelta(days=max_days - 1), end)
        out.append((cur, chunk_end))
        cur = chunk_end + timedelta(days=1)
    return out
