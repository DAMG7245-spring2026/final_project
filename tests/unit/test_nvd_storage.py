"""NVD local NDJSON staging."""

import json
from datetime import date, datetime
from pathlib import Path
from unittest.mock import patch

from ingestion.nvd.storage import (
    iter_curated_ndjson,
    rehydrate_curated_row,
    transform_raw_ndjson_to_curated,
)
from tests.unit.test_nvd_transform import MINIMAL_VULN


def test_transform_raw_to_curated_roundtrip_rehydrate(tmp_path: Path):
    raw_path = tmp_path / "raw.jsonl"
    cur_path = tmp_path / "cur.ndjson"
    raw_path.write_text(json.dumps(MINIMAL_VULN) + "\n", encoding="utf-8")

    stats = transform_raw_ndjson_to_curated(raw_path, cur_path, log_skips=False)
    assert stats == {"lines_in": 1, "transformed": 1, "skipped": 0}

    line = cur_path.read_text(encoding="utf-8").strip()
    d = json.loads(line)
    assert isinstance(d["published_date"], str)
    assert isinstance(d["last_modified"], str)

    rh = rehydrate_curated_row(d)
    assert rh["published_date"] == date(2024, 2, 13)
    assert isinstance(rh["last_modified"], datetime)

    rows = list(iter_curated_ndjson(cur_path))
    assert len(rows) == 1
    assert rows[0]["cve_id"] == "CVE-2024-21413"
    assert isinstance(rows[0]["published_date"], date)


@patch("ingestion.nvd.storage.s3_upload_file")
def test_transform_local_raw_to_s3_curated(mock_upload, tmp_path: Path):
    raw_path = tmp_path / "raw.jsonl"
    raw_path.write_text(json.dumps(MINIMAL_VULN) + "\n", encoding="utf-8")
    out_uri = "s3://test-bucket/nvd/curated/2024-02.ndjson"

    captured: dict[str, str] = {}

    def _grab(local_path: str, uri: str, **kwargs: object) -> None:
        captured["body"] = Path(local_path).read_text(encoding="utf-8")
        captured["uri"] = uri

    mock_upload.side_effect = _grab

    stats = transform_raw_ndjson_to_curated(raw_path, out_uri, log_skips=False)
    assert stats == {"lines_in": 1, "transformed": 1, "skipped": 0}
    mock_upload.assert_called_once()
    assert captured["uri"] == out_uri
    d = json.loads(captured["body"].strip())
    assert d["cve_id"] == "CVE-2024-21413"


@patch("ingestion.nvd.storage.s3_iter_text_lines")
def test_transform_s3_raw_to_local_curated(mock_lines, tmp_path: Path):
    mock_lines.return_value = iter([json.dumps(MINIMAL_VULN)])
    cur_path = tmp_path / "out.ndjson"
    stats = transform_raw_ndjson_to_curated(
        "s3://b/nvd/raw/x.jsonl", cur_path, log_skips=False
    )
    assert stats == {"lines_in": 1, "transformed": 1, "skipped": 0}
    line = cur_path.read_text(encoding="utf-8").strip()
    assert "CVE-2024-21413" in line


@patch("ingestion.nvd.storage.s3_iter_text_lines")
def test_iter_curated_ndjson_from_s3(mock_lines):
    curated_line = (
        '{"cve_id":"CVE-2024-21413","published_date":"2024-02-13",'
        '"last_modified":"2024-02-14T00:00:00"}'
    )
    mock_lines.return_value = iter([curated_line])
    rows = list(iter_curated_ndjson("s3://b/c.ndjson"))
    assert len(rows) == 1
    assert rows[0]["cve_id"] == "CVE-2024-21413"
    assert rows[0]["published_date"] == date(2024, 2, 13)
