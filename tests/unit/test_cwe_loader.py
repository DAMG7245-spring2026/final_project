"""Tests for ingestion.cwe.loader.load_cwe_records (Snowflake mocked)."""

import json
from pathlib import Path
from unittest.mock import patch

from ingestion.cwe.loader import load_cwe_records


def test_load_cwe_records_skips_deprecated_and_calls_snowflake(tmp_path: Path):
    catalog = {
        "weaknesses": [
            {
                "CWE_ID": 79,
                "Name": "XSS",
                "Abstraction": "Base",
                "Status": "Draft",
                "Description": "Test.",
            },
            {
                "CWE_ID": 999,
                "Name": "Old",
                "Status": "Deprecated",
                "Description": "gone",
            },
        ]
    }
    path = tmp_path / "cat.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")

    captured: list[list] = []

    def fake_load(records):
        captured.append(records)
        return len(records)

    with patch(
        "ingestion.cwe.loader.load_cwe_records_to_snowflake", side_effect=fake_load
    ) as mock_sf:
        n = load_cwe_records(path)

    assert n == 1
    mock_sf.assert_called_once()
    assert len(captured) == 1
    assert len(captured[0]) == 1
    assert captured[0][0]["cwe_id"] == "CWE-79"
