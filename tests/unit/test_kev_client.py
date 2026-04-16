"""Unit tests for KEV client."""

from unittest.mock import MagicMock, patch

from ingestion.kev.client import fetch_kev_catalog


@patch("ingestion.kev.client.httpx.Client")
def test_fetch_kev_catalog_returns_vulnerabilities(mock_client_cls):
    resp = MagicMock()
    resp.json.return_value = {
        "title": "Known Exploited Vulnerabilities Catalog",
        "vulnerabilities": [{"cveID": "CVE-2024-0001"}],
    }
    resp.raise_for_status.return_value = None

    mock_client = MagicMock()
    mock_client.get.return_value = resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None
    mock_client_cls.return_value = mock_client

    out = fetch_kev_catalog()
    assert out == [{"cveID": "CVE-2024-0001"}]


@patch("ingestion.kev.client.httpx.Client")
def test_fetch_kev_catalog_handles_non_list(mock_client_cls):
    resp = MagicMock()
    resp.json.return_value = {"vulnerabilities": {}}
    resp.raise_for_status.return_value = None
    mock_client = MagicMock()
    mock_client.get.return_value = resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None
    mock_client_cls.return_value = mock_client
    assert fetch_kev_catalog() == []
