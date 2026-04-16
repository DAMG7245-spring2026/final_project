"""Unit tests for Snowflake staged MERGE upsert."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ingestion.nvd import snowflake_load


def _sample_record(cve_id: str) -> dict:
    return {
        "cve_id": cve_id,
        "source_identifier": "nist",
        "published_date": "2024-01-01",
        "last_modified": "2024-01-02T00:00:00",
        "vuln_status": "Analyzed",
        "description_en": "desc",
        "cvss_version": "3.1",
        "cvss_score": 7.5,
        "cvss_severity": "HIGH",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "UNCHANGED",
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "exploitability_score": 3.9,
        "impact_score": 3.6,
        "cwe_ids": ["CWE-79"],
        "cpe_matches": [{"criteria": "cpe:2.3:a:vendor:prod:*"}],
        "has_exploit_ref": False,
        "raw_json": {"id": cve_id},
    }


def test_upsert_cve_records_uses_staged_merge_sql_sequence():
    records = [_sample_record("CVE-2024-0001"), _sample_record("CVE-2024-0002")]
    mock_cur = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value = mock_cur
    mock_sf = MagicMock()
    mock_sf.cursor.return_value = mock_ctx

    with patch("ingestion.nvd.snowflake_load.get_snowflake_service", return_value=mock_sf):
        rows = snowflake_load.upsert_cve_records(records)

    assert rows == len(records)
    execute_sqls = [call.args[0] for call in mock_cur.execute.call_args_list]
    assert execute_sqls[0] == snowflake_load.CREATE_STAGING_SQL
    assert execute_sqls[1] == snowflake_load.CREATE_STAGE_SQL
    assert execute_sqls[2] == snowflake_load.TRUNCATE_STAGING_SQL
    assert snowflake_load.MERGE_FROM_STAGING_SQL in execute_sqls
    assert "PUT 'file://" in execute_sqls[3]
    assert "@cve_records_staging_stage/" in execute_sqls[3]
    assert execute_sqls[4].lstrip().startswith("COPY INTO cve_records_staging")
    assert any("COPY INTO cve_cwe_mappings_staging" in s for s in execute_sqls)
    assert any("MERGE INTO cve_cwe_mappings AS t" in s for s in execute_sqls)
    mock_cur.executemany.assert_not_called()


def test_upsert_cve_records_empty_short_circuits():
    with patch("ingestion.nvd.snowflake_load.get_snowflake_service") as mock_get_sf:
        rows = snowflake_load.upsert_cve_records([])
    assert rows == 0
    mock_get_sf.assert_not_called()


def test_mapping_rows_dedupes_and_skips_empty():
    rows = snowflake_load._mapping_rows(
        [
            _sample_record("CVE-2024-0001"),
            {
                "cve_id": "CVE-2024-0001",
                "cwe_ids": ["CWE-79", "CWE-89", ""],
            },
            {
                "cve_id": "CVE-2024-0002",
                "cwe_ids": [],
            },
            {
                "cwe_ids": ["CWE-22"],
            },
        ]
    )
    assert rows == [
        {
            "mapping_id": "CVE-2024-0001|CWE-79|nvd",
            "cve_id": "CVE-2024-0001",
            "cwe_id": "CWE-79",
            "mapping_source": "nvd",
            "mapping_type": "PrimaryOrSecondary",
        },
        {
            "mapping_id": "CVE-2024-0001|CWE-89|nvd",
            "cve_id": "CVE-2024-0001",
            "cwe_id": "CWE-89",
            "mapping_source": "nvd",
            "mapping_type": "PrimaryOrSecondary",
        },
    ]
