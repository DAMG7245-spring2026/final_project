"""Airflow DAG helper: nvd month window and S3 key parsing."""

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_DAGS = _REPO / "airflow" / "dags"
if str(_DAGS) not in sys.path:
    sys.path.insert(0, str(_DAGS))

from lib.nvd_months import (  # noqa: E402
    NVD_BATCH_MONTH_ARGS,
    in_nvd_batch_window,
    nvd_month_op_args,
    ym_tuple_from_key,
)


def test_month_count_2020_only():
    assert len(nvd_month_op_args()) == 12
    assert NVD_BATCH_MONTH_ARGS[0] == [2020, 1]
    assert NVD_BATCH_MONTH_ARGS[-1] == [2020, 12]


@pytest.mark.parametrize(
    "key,expected",
    [
        ("nvd/raw/2020-06.jsonl", (2020, 6)),
        ("prefix/nvd/raw/2020-12.jsonl", (2020, 12)),
        ("nvd/curated/2020-01.ndjson", (2020, 1)),
        ("nvd/raw/2021-01.jsonl", (2021, 1)),
        ("bad", None),
    ],
)
def test_ym_tuple_from_key(key: str, expected):
    assert ym_tuple_from_key(key) == expected


def test_in_window():
    assert in_nvd_batch_window((2020, 1))
    assert in_nvd_batch_window((2020, 12))
    assert not in_nvd_batch_window((2019, 12))
    assert not in_nvd_batch_window((2021, 1))
