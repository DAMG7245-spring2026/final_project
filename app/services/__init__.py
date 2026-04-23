"""Services package — lazy attribute access.

Submodules (``snowflake``, ``redis_cache``, ``s3_storage``, ``neo4j_service``,
etc.) are only imported when their symbols are actually accessed. This keeps
transitive driver imports (``neo4j``, ``redis``) off the import path for
callers that only need one service — notably the Airflow DAG runtime image,
which ships with a trimmed ``requirements-dag-runtime.txt`` and must not pay
for packages it never uses.

Public API is unchanged: ``from app.services import get_snowflake_service``
still works and is still re-exported via ``__all__``.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

# Map each re-exported name to (submodule_name, attr_name_in_submodule).
_LAZY_ATTRS: dict[str, tuple[str, str]] = {
    "SnowflakeService": ("snowflake", "SnowflakeService"),
    "get_snowflake_service": ("snowflake", "get_snowflake_service"),
    "RedisCache": ("redis_cache", "RedisCache"),
    "CacheKeys": ("redis_cache", "CacheKeys"),
    "get_redis_cache": ("redis_cache", "get_redis_cache"),
    "S3Storage": ("s3_storage", "S3Storage"),
    "get_s3_storage": ("s3_storage", "get_s3_storage"),
    "Neo4jService": ("neo4j_service", "Neo4jService"),
    "get_neo4j_service": ("neo4j_service", "get_neo4j_service"),
}

__all__ = list(_LAZY_ATTRS)


def __getattr__(name: str) -> Any:
    try:
        submodule, attr = _LAZY_ATTRS[name]
    except KeyError as exc:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        ) from exc
    module = import_module(f".{submodule}", __name__)
    value = getattr(module, attr)
    # Cache on the package module so subsequent lookups skip this function.
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    # Help autocomplete and ``dir()`` show the re-exported names.
    return sorted(list(globals().keys()) + list(_LAZY_ATTRS.keys()))
