"""Snowflake-backed usage logging for LLM and Cortex calls."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.services.snowflake import get_snowflake_service

logger = logging.getLogger(__name__)

_OPENAI_PRICE_PER_1M: dict[str, tuple[float, float]] = {
    # Approximate USD price per 1M tokens (input, output).
    # Keep updated with vendor pricing.
    "gpt-4o": (2.5, 10.0),
    "gpt-4o-mini": (0.15, 0.6),
}


def _usage_field(usage: Any, key: str) -> int | None:
    if usage is None:
        return None
    if isinstance(usage, dict):
        val = usage.get(key)
    else:
        val = getattr(usage, key, None)
    return int(val) if val is not None else None


def estimate_openai_cost_usd(
    model: str | None,
    prompt_tokens: int | None,
    completion_tokens: int | None,
) -> float | None:
    """Estimate cost in USD using a small static model price map."""
    if not model:
        return None
    prices = _OPENAI_PRICE_PER_1M.get(model.strip().lower())
    if not prices:
        return None
    in_price, out_price = prices
    p = int(prompt_tokens or 0)
    c = int(completion_tokens or 0)
    return (p / 1_000_000.0) * in_price + (c / 1_000_000.0) * out_price


def log_llm_usage(
    *,
    source: str,
    operation: str,
    provider: str,
    model: str | None = None,
    usage: Any = None,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    total_tokens: int | None = None,
    estimated_cost_usd: float | None = None,
    success: bool = True,
    error_message: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Best-effort insert into llm_usage_log; never raises."""
    p_tokens = prompt_tokens if prompt_tokens is not None else _usage_field(usage, "prompt_tokens")
    c_tokens = (
        completion_tokens if completion_tokens is not None else _usage_field(usage, "completion_tokens")
    )
    t_tokens = total_tokens if total_tokens is not None else _usage_field(usage, "total_tokens")

    cost = estimated_cost_usd
    if cost is None and provider.strip().lower() == "openai":
        cost = estimate_openai_cost_usd(model=model, prompt_tokens=p_tokens, completion_tokens=c_tokens)

    try:
        get_snowflake_service().execute_write(
            """
            INSERT INTO llm_usage_log (
                source,
                operation,
                provider,
                model,
                prompt_tokens,
                completion_tokens,
                total_tokens,
                estimated_cost_usd,
                success,
                error_message,
                metadata
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, PARSE_JSON(%s)
            )
            """,
            (
                source,
                operation,
                provider,
                model,
                p_tokens,
                c_tokens,
                t_tokens,
                cost,
                success,
                error_message,
                json.dumps(metadata) if metadata is not None else None,
            ),
        )
    except Exception as exc:  # pragma: no cover - intentionally non-fatal
        logger.warning("Failed to write llm_usage_log: %s", exc)


def log_cortex_embed_search(
    *,
    operation: str,
    model: str,
    query: str,
    top_k: int,
    section_names: list[str] | None = None,
    cve_ids: list[str] | None = None,
    cwe_ids: list[str] | None = None,
    mitre_tech_ids: list[str] | None = None,
    advisory_ids: list[str] | None = None,
    min_score: float | None = None,
    success: bool = True,
    error_message: str | None = None,
    result_count: int | None = None,
) -> None:
    """Log a Snowflake Cortex embed-powered search call."""
    log_llm_usage(
        source="api",
        operation=operation,
        provider="snowflake_cortex",
        model=model,
        success=success,
        error_message=error_message,
        metadata={
            "query_char_length": len(query),
            "top_k": top_k,
            "section_name_count": len(section_names or []),
            "cve_id_count": len(cve_ids or []),
            "cwe_id_count": len(cwe_ids or []),
            "mitre_tech_id_count": len(mitre_tech_ids or []),
            "advisory_id_count": len(advisory_ids or []),
            "min_score": min_score,
            "embed_calls": 1,
            "result_count": result_count,
        },
    )
