"""LiteLLM-based LLM router with per-task model mapping, token/cost tracking,
daily budget enforcement, and structured JSON logging.

Design
------
- Every outbound LLM call in the app goes through `LLMRouter.complete()`.
- Each call is tagged with a `task` (see LLMTask); the router picks the model
  from Settings.llm_model_<task>. This lets us swap models per task (e.g.
  cheap gpt-4o-mini for classification, stronger gpt-4o for Cypher/answer)
  without touching call sites.
- Token counts + cost are pulled from the provider response via
  `litellm.completion_cost`, then added to a Redis daily counter keyed by
  the UTC date. When the counter crosses `llm_daily_budget_usd`,
  `complete()` raises `BudgetExceededError` (or just warns when
  `llm_budget_enforce` is False — useful during eval runs).
- A structured JSON log line is emitted for every call so downstream tooling
  (e.g. a notebook, Grafana) can slice by task / model / day.

Why LiteLLM and not the OpenAI SDK directly: LiteLLM gives us (1) multi-provider
routing behind a single `completion()` surface, (2) built-in cost computation
that stays accurate as provider price-lists change, and (3) a single place to
centralize retries + fallbacks later.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator

import litellm
import redis
import structlog

from app.config import get_settings

log = structlog.get_logger(__name__)


class LLMTask(str, Enum):
    """Known LLM call sites in this project.

    Adding a new task: (1) add an enum value, (2) add a matching
    `llm_model_<task>` setting in app/config.py, (3) route through
    `LLMRouter.complete(task=LLMTask.X, ...)`.
    """

    CYPHER_GENERATION = "cypher_generation"
    ANSWER_GENERATION = "answer_generation"
    DOCTYPE_CLASSIFICATION = "doctype_classification"
    RAG_ROUTING = "rag_routing"
    DEFAULT = "default"


class BudgetExceededError(RuntimeError):
    """Raised when today's spend would exceed llm_daily_budget_usd."""

    def __init__(self, spent_usd: float, budget_usd: float, task: str):
        self.spent_usd = spent_usd
        self.budget_usd = budget_usd
        self.task = task
        super().__init__(
            f"Daily LLM budget exceeded: spent ${spent_usd:.4f} / "
            f"${budget_usd:.2f} (task={task})"
        )


@dataclass
class CallRecord:
    """Result of one LLM call — what callers and logs see."""

    task: str
    model: str
    request_id: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    latency_ms: int
    response: Any  # raw litellm ModelResponse; caller unpacks as usual
    daily_spend_usd: float  # running total after this call
    extra: dict[str, Any] = field(default_factory=dict)


def _utc_date_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class LLMRouter:
    """Single entry point for every LLM call in the app.

    Thread-safe for the common case of multiple FastAPI workers sharing one
    instance: the budget counter lives in Redis (atomic INCRBYFLOAT), and the
    in-process fallback counter is guarded by a Lock.
    """

    BUDGET_KEY_PREFIX = "llm:budget:usd:"
    BUDGET_KEY_TTL_SEC = 60 * 60 * 48  # keep 2 days so we can audit yesterday

    def __init__(self, redis_client: redis.Redis | None = None) -> None:
        s = get_settings()
        self._settings = s
        self._task_to_model: dict[str, str] = {
            LLMTask.CYPHER_GENERATION.value: s.llm_model_cypher_generation,
            LLMTask.ANSWER_GENERATION.value: s.llm_model_answer_generation,
            LLMTask.DOCTYPE_CLASSIFICATION.value: s.llm_model_doctype_classification,
            LLMTask.RAG_ROUTING.value: s.llm_model_rag_routing,
            LLMTask.DEFAULT.value: s.llm_model_default,
        }
        self._redis = redis_client
        # In-process fallback when Redis is unavailable. Keyed by UTC date so
        # rollover happens automatically.
        self._local_spend: dict[str, float] = {}
        self._lock = threading.Lock()

        # Make LiteLLM pick up the OpenAI key from our pydantic settings even
        # when the env var isn't exported (e.g. when run from a notebook).
        if s.openai_api_key and not os.environ.get("OPENAI_API_KEY"):
            os.environ["OPENAI_API_KEY"] = s.openai_api_key

    # ---------- public API ----------

    def model_for(self, task: LLMTask | str) -> str:
        key = task.value if isinstance(task, LLMTask) else task
        return self._task_to_model.get(key, self._task_to_model[LLMTask.DEFAULT.value])

    def complete(
        self,
        *,
        task: LLMTask | str,
        messages: list[dict[str, Any]],
        response_format: Any | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: Any | None = None,
        temperature: float = 0,
        max_tokens: int | None = None,
        model_override: str | None = None,
        extra_log: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> CallRecord:
        """Run a completion, enforce budget, record cost, emit structured log.

        `response_format` accepts either a Pydantic BaseModel subclass
        (LiteLLM forwards it to OpenAI's structured-output path) or a raw
        JSON-schema dict — mirrors the OpenAI SDK surface.
        """
        task_key = task.value if isinstance(task, LLMTask) else task
        model = model_override or self.model_for(task_key)
        request_id = uuid.uuid4().hex[:12]

        # Pre-flight budget check — refuse the call early rather than pay
        # for a response we'd reject anyway.
        self._assert_budget_available(task_key, model, request_id)

        call_kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            call_kwargs["max_tokens"] = max_tokens
        if response_format is not None:
            call_kwargs["response_format"] = response_format
        if tools is not None:
            call_kwargs["tools"] = tools
        if tool_choice is not None:
            call_kwargs["tool_choice"] = tool_choice
        call_kwargs.update(kwargs)

        t0 = time.perf_counter()
        try:
            resp = litellm.completion(**call_kwargs)
        except Exception:
            log.exception(
                "llm_call_failed",
                task=task_key,
                model=model,
                request_id=request_id,
                latency_ms=int((time.perf_counter() - t0) * 1000),
                **(extra_log or {}),
            )
            raise
        latency_ms = int((time.perf_counter() - t0) * 1000)

        usage = getattr(resp, "usage", None) or {}
        prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        total_tokens = int(getattr(usage, "total_tokens", 0) or prompt_tokens + completion_tokens)

        cost_usd = self._safe_completion_cost(resp, model)
        daily_spend = self._increment_spend(cost_usd)

        record = CallRecord(
            task=task_key,
            model=model,
            request_id=request_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            response=resp,
            daily_spend_usd=daily_spend,
            extra=extra_log or {},
        )
        log.info(
            "llm_call",
            task=task_key,
            model=model,
            request_id=request_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost_usd=round(cost_usd, 6),
            daily_spend_usd=round(daily_spend, 6),
            daily_budget_usd=self._settings.llm_daily_budget_usd,
            latency_ms=latency_ms,
            **(extra_log or {}),
        )
        return record

    def stream_complete(
        self,
        *,
        task: LLMTask | str,
        messages: list[dict[str, Any]],
        temperature: float = 0,
        max_tokens: int | None = None,
        model_override: str | None = None,
        extra_log: dict[str, Any] | None = None,
        usage_sink: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        """Streaming version of complete(). Yields token strings; logs usage after the stream ends.

        If ``usage_sink`` is provided, it is populated after the stream ends
        with ``prompt_tokens``, ``completion_tokens``, ``cost_usd``,
        ``daily_spend_usd``, ``daily_budget_usd`` — lets callers surface
        usage without parsing log lines.
        """
        task_key = task.value if isinstance(task, LLMTask) else task
        model = model_override or self.model_for(task_key)
        request_id = uuid.uuid4().hex[:12]

        self._assert_budget_available(task_key, model, request_id)

        call_kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if max_tokens is not None:
            call_kwargs["max_tokens"] = max_tokens
        call_kwargs.update(kwargs)

        t0 = time.perf_counter()
        try:
            stream = litellm.completion(**call_kwargs)
        except Exception:
            log.exception("llm_stream_failed", task=task_key, model=model, request_id=request_id)
            raise

        prompt_tokens = 0
        completion_tokens = 0
        try:
            for chunk in stream:
                delta = chunk.choices[0].delta.content if chunk.choices else None
                if delta:
                    yield delta
                if hasattr(chunk, "usage") and chunk.usage:
                    prompt_tokens = int(getattr(chunk.usage, "prompt_tokens", 0) or 0)
                    completion_tokens = int(getattr(chunk.usage, "completion_tokens", 0) or 0)
        finally:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            try:
                prompt_cost, completion_cost_val = litellm.cost_per_token(
                    model=model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                )
                cost_usd = prompt_cost + completion_cost_val
            except Exception:
                cost_usd = 0.0
            daily_spend = self._increment_spend(cost_usd)
            if usage_sink is not None:
                usage_sink.update(
                    {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "cost_usd": cost_usd,
                        "daily_spend_usd": daily_spend,
                        "daily_budget_usd": self._settings.llm_daily_budget_usd,
                    }
                )
            log.info(
                "llm_stream_call",
                task=task_key,
                model=model,
                request_id=request_id,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=round(cost_usd, 6),
                daily_spend_usd=round(daily_spend, 6),
                daily_budget_usd=self._settings.llm_daily_budget_usd,
                latency_ms=latency_ms,
                **(extra_log or {}),
            )

    # ---------- budget ----------

    def get_daily_spend_usd(self, date_key: str | None = None) -> float:
        """Return running USD spend for a UTC day (today by default)."""
        date_key = date_key or _utc_date_key()
        redis_key = self.BUDGET_KEY_PREFIX + date_key
        if self._redis is not None:
            try:
                v = self._redis.get(redis_key)
                return float(v) if v is not None else 0.0
            except Exception as e:
                log.warning("redis_get_failed_using_local", error=str(e))
        with self._lock:
            return self._local_spend.get(date_key, 0.0)

    def get_remaining_budget_usd(self) -> float:
        return max(0.0, self._settings.llm_daily_budget_usd - self.get_daily_spend_usd())

    def reset_daily_spend(self, date_key: str | None = None) -> None:
        """Manual reset — useful for tests / notebooks. Not called in prod."""
        date_key = date_key or _utc_date_key()
        redis_key = self.BUDGET_KEY_PREFIX + date_key
        if self._redis is not None:
            try:
                self._redis.delete(redis_key)
            except Exception as e:
                log.warning("redis_del_failed", error=str(e))
        with self._lock:
            self._local_spend.pop(date_key, None)

    def _assert_budget_available(self, task: str, model: str, request_id: str) -> None:
        spent = self.get_daily_spend_usd()
        budget = self._settings.llm_daily_budget_usd
        if spent < budget:
            return
        log.warning(
            "llm_budget_exceeded",
            task=task,
            model=model,
            request_id=request_id,
            daily_spend_usd=round(spent, 6),
            daily_budget_usd=budget,
            enforce=self._settings.llm_budget_enforce,
        )
        if self._settings.llm_budget_enforce:
            raise BudgetExceededError(spent, budget, task)

    def _increment_spend(self, delta_usd: float) -> float:
        if delta_usd <= 0:
            return self.get_daily_spend_usd()
        date_key = _utc_date_key()
        redis_key = self.BUDGET_KEY_PREFIX + date_key
        if self._redis is not None:
            try:
                new_total = float(self._redis.incrbyfloat(redis_key, delta_usd))
                self._redis.expire(redis_key, self.BUDGET_KEY_TTL_SEC)
                return new_total
            except Exception as e:
                log.warning("redis_incrbyfloat_failed_using_local", error=str(e))
        with self._lock:
            self._local_spend[date_key] = self._local_spend.get(date_key, 0.0) + delta_usd
            return self._local_spend[date_key]

    # ---------- helpers ----------

    @staticmethod
    def _safe_completion_cost(resp: Any, model: str) -> float:
        # LiteLLM's price table can miss brand-new models; swallow and return
        # 0.0 rather than blocking the call. Budget tracking degrades to "only
        # known models count" — better than crashing on an unknown SKU.
        try:
            return float(litellm.completion_cost(completion_response=resp, model=model))
        except Exception as e:
            log.warning("cost_lookup_failed", model=model, error=str(e))
            return 0.0


_router: LLMRouter | None = None
_router_lock = threading.Lock()


def get_llm_router() -> LLMRouter:
    """Process-wide singleton. Wires Redis from app.services.redis_cache
    lazily so importing this module doesn't force a Redis connection."""
    global _router
    if _router is not None:
        return _router
    with _router_lock:
        if _router is None:
            redis_client: redis.Redis | None = None
            try:
                s = get_settings()
                redis_client = redis.Redis(
                    host=s.redis_host,
                    port=s.redis_port,
                    db=s.redis_db,
                    decode_responses=True,
                    socket_connect_timeout=1,
                )
                redis_client.ping()
            except Exception as e:
                log.warning(
                    "redis_unavailable_using_local_budget",
                    error=str(e),
                )
                redis_client = None
            _router = LLMRouter(redis_client=redis_client)
    return _router
