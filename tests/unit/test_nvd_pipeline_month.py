"""ingest_lastmod_month wiring (mocked I/O)."""

from datetime import date
from pathlib import Path
from unittest.mock import patch

import pytest

from ingestion.nvd.pipeline import (
    ingest_lastmod_month_to_disk_and_snowflake,
    ingest_lastmod_month_to_s3_and_snowflake,
)


@patch("ingestion.nvd.pipeline.load_curated_file_to_snowflake")
@patch("ingestion.nvd.pipeline.transform_raw_file_to_curated")
@patch("ingestion.nvd.pipeline.fetch_delta_to_raw_file")
def test_ingest_month_calls_pipeline_with_paths_and_batch_2000(
    mock_fetch, mock_transform, mock_load, tmp_path: Path
):
    mock_fetch.return_value = {"fetched": 10, "pages": 1}
    mock_transform.return_value = {
        "lines_in": 10,
        "transformed": 10,
        "skipped": 0,
    }
    mock_load.return_value = {
        "lines_read": 10,
        "rows_upserted": 10,
        "batches": 1,
    }

    base = tmp_path / "nvd"
    out = ingest_lastmod_month_to_disk_and_snowflake(
        2025,
        1,
        base_dir=base,
        snowflake_batch_size=2000,
        api_key="test-key",
    )

    raw_expected = base / "raw" / "2025-01.jsonl"
    cur_expected = base / "curated" / "2025-01.ndjson"

    mock_fetch.assert_called_once()
    fargs, fkwargs = mock_fetch.call_args
    assert fargs[0] == date(2025, 1, 1)
    assert fargs[1] == date(2025, 1, 31)
    assert fargs[2] == raw_expected
    assert fargs[3] == "test-key"

    mock_transform.assert_called_once_with(raw_expected, cur_expected)
    mock_load.assert_called_once_with(cur_expected, batch_size=2000)

    assert out["year"] == 2025
    assert out["month"] == 1
    assert out["start_date"] == "2025-01-01"
    assert out["end_date"] == "2025-01-31"
    assert out["fetch"] == mock_fetch.return_value
    assert out["transform"] == mock_transform.return_value
    assert out["load"] == mock_load.return_value


@patch("ingestion.nvd.pipeline.load_curated_file_to_snowflake")
@patch("ingestion.nvd.pipeline.transform_raw_file_to_curated")
@patch("ingestion.nvd.pipeline.fetch_delta_to_raw_file")
def test_ingest_february_leap_year(mock_fetch, mock_transform, mock_load, tmp_path: Path):
    mock_fetch.return_value = {"fetched": 0, "pages": 0}
    mock_transform.return_value = {"lines_in": 0, "transformed": 0, "skipped": 0}
    mock_load.return_value = {"lines_read": 0, "rows_upserted": 0, "batches": 0}

    ingest_lastmod_month_to_disk_and_snowflake(2024, 2, base_dir=tmp_path / "nvd")

    fargs, _ = mock_fetch.call_args
    assert fargs[0] == date(2024, 2, 1)
    assert fargs[1] == date(2024, 2, 29)


@patch("ingestion.nvd.pipeline.load_curated_file_to_snowflake")
@patch("ingestion.nvd.pipeline.transform_raw_file_to_curated")
@patch("ingestion.nvd.pipeline.fetch_delta_to_raw_file")
def test_ingest_month_s3_uses_bucket_uris_and_batch_2000(
    mock_fetch, mock_transform, mock_load, tmp_path: Path
):
    mock_fetch.return_value = {"fetched": 3, "pages": 1}
    mock_transform.return_value = {
        "lines_in": 3,
        "transformed": 3,
        "skipped": 0,
    }
    mock_load.return_value = {
        "lines_read": 3,
        "rows_upserted": 3,
        "batches": 1,
    }

    out = ingest_lastmod_month_to_s3_and_snowflake(
        2025,
        3,
        bucket="my-bucket",
        prefix="nvd",
        snowflake_batch_size=2000,
        api_key="k",
    )

    raw_uri = "s3://my-bucket/nvd/raw/2025-03.jsonl"
    curated_uri = "s3://my-bucket/nvd/curated/2025-03.ndjson"

    mock_fetch.assert_called_once()
    fargs, fkwargs = mock_fetch.call_args
    assert fargs[0] == date(2025, 3, 1)
    assert fargs[1] == date(2025, 3, 31)
    assert fargs[2] == raw_uri
    assert fargs[3] == "k"

    mock_transform.assert_called_once_with(raw_uri, curated_uri)
    mock_load.assert_called_once_with(curated_uri, batch_size=2000)

    assert out["raw_uri"] == raw_uri
    assert out["curated_uri"] == curated_uri
    assert out["fetch"] == mock_fetch.return_value


@patch("app.config.get_settings")
def test_ingest_month_s3_requires_bucket(mock_settings):
    mock_settings.return_value.s3_bucket = ""
    with pytest.raises(ValueError, match="S3 bucket"):
        ingest_lastmod_month_to_s3_and_snowflake(2025, 1)
