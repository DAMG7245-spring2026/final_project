"""Unit tests for KEV enrichment bulk/fallback paths."""

from unittest.mock import MagicMock, patch

from ingestion.kev.enricher import _to_stage_row, run_kev_sync


def _mock_sf_with_cursor(cur: MagicMock) -> MagicMock:
    ctx = MagicMock()
    ctx.__enter__.return_value = cur
    sf = MagicMock()
    sf.cursor.return_value = ctx
    return sf


def test_run_kev_sync_uses_bulk_path_and_logs_summary(caplog):
    feed = [
        {
            "cveID": "CVE-2024-1234",
            "dateAdded": "2024-01-05",
            "dueDate": "2024-02-10",
            "requiredAction": "Patch now",
            "knownRansomwareCampaignUse": "Known",
            "vendorProject": "VendorA",
            "product": "ProdA",
        }
    ]
    cur = MagicMock()
    cur.fetchone.return_value = (1, 0)
    sf = _mock_sf_with_cursor(cur)

    with patch("ingestion.kev.enricher._get_snowflake_service", return_value=sf):
        with caplog.at_level("INFO"):
            stats = run_kev_sync(feed_rows=feed)

    assert stats["mode"] == "bulk"
    sqls = [c.args[0] for c in cur.execute.call_args_list]
    assert any("COPY INTO kev_enrichment_staging" in s for s in sqls)
    assert any("MERGE INTO cve_records AS t" in s for s in sqls)
    assert any("MERGE INTO kev_pending_fetch AS q" in s for s in sqls)
    assert "kev_sync_summary" in caplog.text


def test_run_kev_sync_fallback_logs_warning(caplog):
    feed = [{"cveID": "CVE-2024-9999", "dateAdded": "2024-01-01"}]
    cur = MagicMock()
    cur.fetchone.return_value = (0, 1)
    first = {"n": 0}

    def _execute(sql: str, *args, **kwargs):
        if "PUT 'file://" in sql and first["n"] == 0:
            first["n"] += 1
            raise RuntimeError("put failed")
        return None

    cur.execute.side_effect = _execute
    sf = _mock_sf_with_cursor(cur)

    with patch("ingestion.kev.enricher._get_snowflake_service", return_value=sf):
        with caplog.at_level("INFO"):
            stats = run_kev_sync(feed_rows=feed)

    assert stats["mode"] == "fallback"
    assert cur.executemany.called
    assert "kev_sync_fallback" in caplog.text


def test_run_kev_sync_dedupes_duplicate_cve_ids():
    feed = [
        {"cveID": "CVE-2024-1111", "dateAdded": "2024-01-01"},
        {"cveID": "CVE-2024-1111", "dateAdded": "2024-01-02"},
    ]
    cur = MagicMock()
    cur.fetchone.return_value = (1, 0)
    sf = _mock_sf_with_cursor(cur)

    with patch("ingestion.kev.enricher._get_snowflake_service", return_value=sf):
        stats = run_kev_sync(feed_rows=feed)

    assert stats["feed_size"] == 2
    assert stats["deduped_rows"] == 1


def test_to_stage_row_clips_bounded_columns():
    row = _to_stage_row(
        {
            "cveID": "CVE-2026-1111",
            "knownRansomwareCampaignUse": "X" * 80,
            "vendorProject": "V" * 140,
            "product": "P" * 140,
        }
    )
    assert row is not None
    assert len(row["kev_ransomware_use"]) == 50
    assert len(row["kev_vendor_project"]) == 100
    assert len(row["kev_product"]) == 100
