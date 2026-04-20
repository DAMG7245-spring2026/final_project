"""Central structured-logging configuration.

Single source of truth for how the app emits logs:

- `structlog` wraps stdlib `logging`, so third-party libraries that log via
  `logging.getLogger(...)` (litellm, uvicorn, neo4j, httpx, ...) land in the
  same pipeline as our own `structlog.get_logger()` calls.
- In production (`log_format=json`) every line is a single JSON object with
  a stable `event` key — ready for Loki / CloudWatch / GCP Logging.
- In dev (`log_format=console`) the same events are rendered as colorized
  key=value for human reading.
- `log_format=auto` picks console when `Settings.debug` is True, else json.

Call `configure_logging()` once at process entry:
- `app/main.py` — FastAPI lifespan / module import
- Any script under `scripts/` that runs out-of-process
- `streamlit_cti/` entry point

Idempotent: calling it twice is a no-op.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys

import structlog

from app.config import get_settings

_CONFIGURED = False


def _resolve_format(requested: str, debug: bool) -> str:
    if requested == "auto":
        return "console" if debug else "json"
    if requested not in {"json", "console"}:
        return "json"
    return requested


def configure_logging(
    *,
    level: str | None = None,
    fmt: str | None = None,
    log_file: str | None = None,
    force: bool = False,
) -> None:
    """Set up structlog + stdlib logging to emit one consistent stream.

    All arguments override the matching `Settings.log_*` fields. `force=True`
    re-applies config even if already set (useful in notebooks / tests).
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    s = get_settings()
    level_name = (level or s.log_level or "INFO").upper()
    log_level = getattr(logging, level_name, logging.INFO)
    render_format = _resolve_format(fmt or s.log_format, s.debug)
    file_path = log_file if log_file is not None else s.log_file

    # Shared processors — run on BOTH native structlog loggers and on stdlib
    # loggers that we wrap via ProcessorFormatter below.
    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # structlog side: emit events as a dict to the ProcessorFormatter.
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # stdlib side: a Formatter that knows how to render either a structlog
    # event-dict (from our logger) or a plain LogRecord (from libraries).
    renderer: structlog.types.Processor = (
        structlog.dev.ConsoleRenderer(colors=True)
        if render_format == "console"
        else structlog.processors.JSONRenderer()
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    # Replace existing handlers — otherwise FastAPI / uvicorn's defaults
    # duplicate lines.
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    if file_path:
        file_handler = logging.handlers.RotatingFileHandler(
            file_path, maxBytes=50 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    root.setLevel(log_level)

    # Quiet down libraries that spam INFO by default. These levels are chosen
    # so we still see warnings/errors but not every HTTP request.
    for noisy in ("httpx", "httpcore", "urllib3", "openai", "LiteLLM"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Thin wrapper so callers don't need to import structlog directly."""
    return structlog.get_logger(name)
