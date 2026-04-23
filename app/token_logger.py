"""Persists per-call LLM token usage to Snowflake for cost analytics.

Two calling patterns:
  Scripts (extract_triplets, align_entities, infer_relations):
    Pass cur=<existing Snowflake cursor> — reuses the script's open connection.
  App layer (LLMRouter / text2cypher):
    Omit cur; token_logger manages a lazy persistent connection with autocommit.

Failures are always suppressed so logging never blocks the calling pipeline.
"""
import threading
import uuid
from typing import Any

import structlog

log = structlog.get_logger(__name__)

_lock = threading.Lock()
_persistent_conn: Any = None

_INSERT_SQL = """
    INSERT INTO llm_token_log
        (pipeline_stage, model, request_id,
         prompt_tokens, completion_tokens, total_tokens,
         advisory_id)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
"""


def _get_persistent_conn():
    global _persistent_conn
    if _persistent_conn is not None:
        try:
            with _persistent_conn.cursor() as c:
                c.execute("SELECT 1")
            return _persistent_conn
        except Exception:
            try:
                _persistent_conn.close()
            except Exception:
                pass
            _persistent_conn = None

    from app.config import get_settings
    import snowflake.connector

    s = get_settings()
    _persistent_conn = snowflake.connector.connect(
        account=s.snowflake_account,
        user=s.snowflake_user,
        password=s.snowflake_password,
        database=s.snowflake_database,
        schema=s.snowflake_schema,
        warehouse=s.snowflake_warehouse,
        autocommit=True,
    )
    return _persistent_conn


def log_llm_call(
    *,
    pipeline_stage: str,
    model: str,
    request_id: str | None = None,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int | None = None,
    advisory_id: str | None = None,
    cur: Any = None,
) -> None:
    if request_id is None:
        request_id = uuid.uuid4().hex[:12]
    if total_tokens is None:
        total_tokens = prompt_tokens + completion_tokens

    params = (
        pipeline_stage, model, request_id,
        prompt_tokens, completion_tokens, total_tokens,
        advisory_id,
    )
    try:
        if cur is not None:
            cur.execute(_INSERT_SQL, params)
        else:
            with _lock:
                conn = _get_persistent_conn()
                with conn.cursor() as _cur:
                    _cur.execute(_INSERT_SQL, params)
    except Exception as e:
        log.warning("token_log_failed", stage=pipeline_stage, error=str(e))
