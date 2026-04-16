"""Unit tests for CWE catalog transform (no Snowflake)."""

import json
from pathlib import Path

import pytest

from ingestion.cwe.transform import (
    build_records_and_stats,
    load_transformed_json,
    normalize_description,
    raw_weaknesses_sample_document,
    weakness_to_record,
)


def test_weakness_to_record_skips_deprecated():
    assert (
        weakness_to_record({"CWE_ID": 79, "Status": "Deprecated", "Name": "X"})
        is None
    )


def test_weakness_to_record_maps_basic():
    r = weakness_to_record(
        {
            "CWE_ID": 79,
            "Name": "Cross-site Scripting",
            "Abstraction": "Base",
            "Status": "Incomplete",
            "Description": "Foo bar.",
        }
    )
    assert r is not None
    assert r["cwe_id"] == "CWE-79"
    assert r["name"] == "Cross-site Scripting"
    assert r["abstraction"] == "Base"
    assert r["status"] == "Incomplete"
    assert r["description"] == "Foo bar."
    assert r["is_deprecated"] is False


def test_weakness_to_record_cwe_id_string():
    r = weakness_to_record(
        {"CWE_ID": "22", "Name": "N", "Status": "Draft", "Description": ""}
    )
    assert r["cwe_id"] == "CWE-22"


def test_normalize_description_dict():
    assert normalize_description({"#text": "hello"}) == "hello"
    assert normalize_description({"text": "x"}) == "x"


def test_build_records_and_stats():
    data = {
        "weaknesses": [
            {
                "CWE_ID": 1,
                "Name": "A",
                "Status": "Deprecated",
                "Description": "",
            },
            {
                "CWE_ID": 2,
                "Name": "B",
                "Status": "Draft",
                "Description": "d",
            },
        ]
    }
    records, stats = build_records_and_stats(data)
    assert stats["raw_weaknesses"] == 2
    assert stats["skipped_deprecated"] == 1
    assert stats["kept"] == 1
    assert len(records) == 1
    assert records[0]["cwe_id"] == "CWE-2"


def test_load_transformed_json_roundtrip(tmp_path: Path):
    rows = [
        {
            "cwe_id": "CWE-99",
            "name": "N",
            "abstraction": "Class",
            "status": "Draft",
            "description": "D",
            "is_deprecated": False,
        }
    ]
    p = tmp_path / "t.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    loaded = load_transformed_json(p)
    assert loaded == rows


def test_load_transformed_json_rejects_non_list(tmp_path: Path):
    p = tmp_path / "t.json"
    p.write_text('{"x": 1}', encoding="utf-8")
    with pytest.raises(ValueError, match="array"):
        load_transformed_json(p)


def test_raw_weaknesses_sample_document(tmp_path: Path):
    catalog = tmp_path / "c.json"
    catalog.write_text(
        json.dumps(
            {
                "weaknesses": [
                    {"CWE_ID": 1, "Name": "A", "Status": "Deprecated"},
                    {"CWE_ID": 2, "Name": "B", "Status": "Draft", "Description": "x"},
                ]
            }
        ),
        encoding="utf-8",
    )
    doc = raw_weaknesses_sample_document(catalog, limit=1)
    assert doc["sample_count"] == 1
    assert doc["total_weaknesses_in_file"] == 2
    assert doc["weaknesses"][0]["CWE_ID"] == 1
    assert "CWE-" not in str(doc["weaknesses"][0])
