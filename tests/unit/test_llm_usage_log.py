from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.llm_usage_log import (
    estimate_openai_cost_usd,
    log_cortex_embed_search,
    log_llm_usage,
)


def test_estimate_openai_cost_usd_known_model() -> None:
    cost = estimate_openai_cost_usd("gpt-4o", prompt_tokens=1000, completion_tokens=2000)
    assert cost is not None
    # (1000/1M * 2.5) + (2000/1M * 10.0) = 0.0225
    assert round(cost, 6) == 0.0225


def test_estimate_openai_cost_usd_unknown_model() -> None:
    assert estimate_openai_cost_usd("unknown-model", 100, 100) is None


@patch("app.services.llm_usage_log.get_snowflake_service")
def test_log_llm_usage_writes_openai_row(mock_get_snowflake: MagicMock) -> None:
    svc = MagicMock()
    mock_get_snowflake.return_value = svc

    usage = SimpleNamespace(prompt_tokens=120, completion_tokens=80, total_tokens=200)
    log_llm_usage(
        source="script",
        operation="generate_gold_triplets.extract",
        provider="openai",
        model="gpt-4o",
        usage=usage,
        success=True,
        metadata={"demo_id": "D1"},
    )

    assert svc.execute_write.call_count == 1
    _sql, params = svc.execute_write.call_args.args
    assert params[0] == "script"
    assert params[1] == "generate_gold_triplets.extract"
    assert params[2] == "openai"
    assert params[3] == "gpt-4o"
    assert params[4] == 120
    assert params[5] == 80
    assert params[6] == 200
    assert params[7] is not None  # estimated cost
    assert params[8] is True
    assert params[10] == json.dumps({"demo_id": "D1"})


@patch("app.services.llm_usage_log.get_snowflake_service")
def test_log_cortex_embed_search_writes_cortex_row(mock_get_snowflake: MagicMock) -> None:
    svc = MagicMock()
    mock_get_snowflake.return_value = svc

    log_cortex_embed_search(
        operation="search_advisory_chunks",
        model="snowflake-arctic-embed-l-v2.0",
        query="what is exploited",
        top_k=10,
        cve_ids=["CVE-2024-0001"],
        success=True,
        result_count=3,
    )

    assert svc.execute_write.call_count == 1
    _sql, params = svc.execute_write.call_args.args
    assert params[0] == "api"
    assert params[1] == "search_advisory_chunks"
    assert params[2] == "snowflake_cortex"
    assert params[3] == "snowflake-arctic-embed-l-v2.0"
    assert params[4] is None
    assert params[5] is None
    assert params[6] is None
    assert params[7] is None
    meta = json.loads(params[10])
    assert meta["query_char_length"] == len("what is exploited")
    assert meta["cve_id_count"] == 1
    assert meta["embed_calls"] == 1
    assert meta["result_count"] == 3
