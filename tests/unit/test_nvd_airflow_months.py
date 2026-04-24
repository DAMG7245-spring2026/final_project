"""Airflow DAG helper: nvd month window and S3 key parsing."""

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_DAGS = _REPO / "airflow" / "dags"
if str(_DAGS) not in sys.path:
    sys.path.insert(0, str(_DAGS))

import importlib

import lib.nvd_months as nvd_months  # noqa: E402


def test_month_count_default_window():
    assert len(nvd_months.nvd_month_op_args()) == 12
    assert nvd_months.NVD_BATCH_MONTH_ARGS[0] == [2023, 1]
    assert nvd_months.NVD_BATCH_MONTH_ARGS[-1] == [2023, 12]


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
    assert nvd_months.ym_tuple_from_key(key) == expected


def test_in_window():
    assert nvd_months.in_nvd_batch_window((2023, 1))
    assert nvd_months.in_nvd_batch_window((2023, 12))
    assert not nvd_months.in_nvd_batch_window((2022, 12))
    assert not nvd_months.in_nvd_batch_window((2024, 1))


def test_cti_env_overrides_month_window(monkeypatch):
    monkeypatch.setenv("CTI_NVD_YM_START", "2024-03")
    monkeypatch.setenv("CTI_NVD_YM_END", "2024-04")
    importlib.reload(nvd_months)
    try:
        assert nvd_months.nvd_month_op_args() == [[2024, 3], [2024, 4]]
    finally:
        monkeypatch.delenv("CTI_NVD_YM_START", raising=False)
        monkeypatch.delenv("CTI_NVD_YM_END", raising=False)
        importlib.reload(nvd_months)
