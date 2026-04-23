"""
Shared helpers for the NVD batch DAGs (``nvd_fetch_dag`` / ``nvd_transform_dag``
/ ``nvd_load_dag``) and the ``attack_weekly_dag``.

Responsibilities:
- ``ensure_repo_imports``: add the repo root to ``sys.path`` so ``app.*`` and
  ``ingestion.*`` resolve inside Airflow task callables.
- Batch window constants: the NVD historical backfill covers 2020-01 .. 2020-12,
  expanded as one mapped task per calendar month.
- S3 URI builders / parsers for ``{prefix}/raw/YYYY-MM.jsonl`` and
  ``{prefix}/curated/YYYY-MM.ndjson`` object keys.

This file lives at ``airflow/dags/lib/nvd_months.py``. The DAG modules add
``airflow/dags/`` to ``sys.path`` so they can import this as ``lib.nvd_months``.
"""

from __future__ import annotations

import calendar
import re
import sys
from datetime import date
from pathlib import Path

# airflow/dags/lib/nvd_months.py -> parents[3] == repo root.
_REPO_ROOT = Path(__file__).resolve().parents[3]


def ensure_repo_imports() -> None:
    """Idempotently prepend the repo root to ``sys.path``.

    Called at the top of each task callable so that the first-touch import of
    ``app.*`` / ``ingestion.*`` inside the Airflow worker works, without needing
    to bake the path into the Airflow image.
    """
    root = str(_REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


# ---------- batch window ----------

NVD_BATCH_YEAR = 2020
NVD_BATCH_MONTHS: list[int] = list(range(1, 13))

# Shaped as list[list[int]] (not tuples) because Airflow's mapped
# ``PythonOperator.partial(...).expand(op_args=...)`` expects each element
# to be a sequence passed positionally to the callable.
NVD_BATCH_MONTH_ARGS: list[list[int]] = [[NVD_BATCH_YEAR, m] for m in NVD_BATCH_MONTHS]


def in_nvd_batch_window(ym: tuple[int, int]) -> bool:
    """True iff ``(year, month)`` falls in the 2020 full-year backfill window."""
    y, m = ym
    return y == NVD_BATCH_YEAR and 1 <= m <= 12


def first_last_day(year: int, month: int) -> tuple[date, date]:
    """Return (first_day, last_day) for the given calendar month."""
    last = calendar.monthrange(year, month)[1]
    return date(year, month, 1), date(year, month, last)


# ---------- S3 URI / key helpers ----------


def _ym_str(year: int, month: int) -> str:
    return f"{year:04d}-{month:02d}"


def raw_s3_uri(bucket: str, prefix: str, year: int, month: int) -> str:
    p = prefix.strip("/")
    return f"s3://{bucket}/{p}/raw/{_ym_str(year, month)}.jsonl"


def curated_s3_uri(bucket: str, prefix: str, year: int, month: int) -> str:
    p = prefix.strip("/")
    return f"s3://{bucket}/{p}/curated/{_ym_str(year, month)}.ndjson"


# Matches ``.../YYYY-MM.jsonl`` or ``.../YYYY-MM.ndjson`` at end of key.
_YM_KEY_RE = re.compile(r"(?P<y>\d{4})-(?P<m>\d{2})\.(?:jsonl|ndjson)$")


def ym_tuple_from_key(s3_key: str) -> tuple[int, int] | None:
    """Extract (year, month) from an S3 key ending in ``YYYY-MM.{jsonl,ndjson}``.

    Returns ``None`` when the key doesn't match the expected shape or the
    month is out of range — callers filter these out before dispatching work.
    """
    match = _YM_KEY_RE.search(s3_key)
    if not match:
        return None
    y = int(match.group("y"))
    m = int(match.group("m"))
    if not 1 <= m <= 12:
        return None
    return y, m
