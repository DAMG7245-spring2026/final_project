"""ingestion.monitoring checkpoints and pipeline_runs helpers."""

from datetime import date
from unittest.mock import MagicMock, patch

from ingestion.monitoring.checkpoints import (
    NVD_INCREMENTAL_SOURCE,
    NVD_S3_SLICE_SOURCE,
    resolve_nvd_date_window,
    resolve_nvd_s3_slice_window,
    slice_date_range,
)
from ingestion.monitoring.snowflake_runs import complete_pipeline_run, start_pipeline_run


def test_slice_date_range_splits_weekly():
    assert slice_date_range(date(2024, 1, 1), date(2024, 1, 1), max_days=7) == [
        (date(2024, 1, 1), date(2024, 1, 1))
    ]
    chunks = slice_date_range(date(2024, 1, 1), date(2024, 1, 20), max_days=7)
    assert len(chunks) == 3
    assert chunks[0] == (date(2024, 1, 1), date(2024, 1, 7))
    assert chunks[-1][1] == date(2024, 1, 20)


@patch("ingestion.monitoring.checkpoints.get_checkpoint")
@patch("ingestion.monitoring.checkpoints._cold_start_nvd_start")
def test_resolve_nvd_window_uses_checkpoint(mock_cold, mock_get_cp):
    mock_get_cp.return_value = {"watermark_date": date(2024, 6, 15)}
    mock_cold.return_value = date(2000, 1, 1)
    start, end = resolve_nvd_date_window({}, today_utc=date(2024, 7, 1))
    assert start == date(2024, 6, 16)
    assert end == date(2024, 7, 1)
    mock_get_cp.assert_called_once_with(NVD_INCREMENTAL_SOURCE)
    mock_cold.assert_not_called()


@patch("ingestion.monitoring.checkpoints.get_checkpoint", return_value=None)
@patch("ingestion.monitoring.checkpoints._cold_start_nvd_start", return_value=date(2024, 1, 10))
def test_resolve_nvd_window_cold_start_when_no_checkpoint(_mock_get, _mock_cold):
    start, end = resolve_nvd_date_window({}, today_utc=date(2024, 1, 20))
    assert start == date(2024, 1, 10)
    assert end == date(2024, 1, 20)


def test_resolve_nvd_window_conf_override():
    start, end = resolve_nvd_date_window(
        {"force_start": "2024-02-01", "force_end": "2024-02-05"},
        today_utc=date(2024, 12, 1),
    )
    assert start == date(2024, 2, 1)
    assert end == date(2024, 2, 5)


@patch("app.services.snowflake.get_snowflake_service")
def test_start_and_complete_pipeline_run(mock_get_sf):
    sf = MagicMock()
    mock_get_sf.return_value = sf

    rid = start_pipeline_run(
        dag_id="test_dag",
        source="test",
        logical_source="unit",
        airflow_dag_run_id="dr1",
        airflow_task_id="t1",
    )
    assert len(rid) > 8
    assert sf.execute_write.call_count == 1

    complete_pipeline_run(
        rid,
        status="success",
        stats={"k": "v"},
        records_fetched=10,
        records_new=3,
    )
    assert sf.execute_write.call_count == 2


def test_nvd_incremental_source_constant():
    assert NVD_INCREMENTAL_SOURCE == "nvd_api_last_modified_through"


def test_nvd_s3_slice_source_constant():
    assert NVD_S3_SLICE_SOURCE == "nvd_s3_slice_pipeline_through"


@patch("ingestion.monitoring.checkpoints.get_checkpoint")
def test_resolve_nvd_s3_slice_window_uses_slice_checkpoint(mock_get_cp):
    mock_get_cp.return_value = {"watermark_date": date(2024, 6, 15)}
    start, end = resolve_nvd_s3_slice_window({}, today_utc=date(2024, 7, 1))
    assert start == date(2024, 6, 16)
    assert end == date(2024, 7, 1)
    mock_get_cp.assert_called_once_with(NVD_S3_SLICE_SOURCE)


@patch("ingestion.monitoring.checkpoints.get_checkpoint")
def test_resolve_nvd_date_window_custom_checkpoint_source(mock_get_cp):
    mock_get_cp.return_value = {"watermark_date": date(2024, 3, 1)}
    start, end = resolve_nvd_date_window(
        {},
        today_utc=date(2024, 3, 10),
        checkpoint_source=NVD_S3_SLICE_SOURCE,
    )
    assert start == date(2024, 3, 2)
    assert end == date(2024, 3, 10)
    mock_get_cp.assert_called_once_with(NVD_S3_SLICE_SOURCE)
