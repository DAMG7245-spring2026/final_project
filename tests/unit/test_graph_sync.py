"""Unit tests for Snowflake → Neo4j CVE/CWE/KEV sync."""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

# Stub neo4j only when the driver is not installed; never replace a real package
# (would break later tests that import neo4j.time via app.services.cti_graph).
try:
    import neo4j as _neo4j_check  # noqa: F401
    from neo4j.time import Date as _Neo4jDateCheck  # noqa: F401
except ImportError:
    if "neo4j" not in sys.modules:
        _neo4j_stub = types.ModuleType("neo4j")

        class _GraphDatabase:
            @staticmethod
            def driver(*_a, **_k):
                raise RuntimeError("neo4j driver not configured in this test run")

        _neo4j_stub.GraphDatabase = _GraphDatabase
        _neo4j_stub.Driver = type("Driver", (), {})
        sys.modules["neo4j"] = _neo4j_stub

from ingestion.graph_sync.cve_cwe_kev import (
    _cve_to_neo_row,
    run_cve_cwe_kev_sync,
)


def test_cve_to_neo_row_truncates_long_description():
    long_desc = "x" * 30000
    row = _cve_to_neo_row({"cve_id": "CVE-2024-1", "description_en": long_desc})
    assert len(row["description_en"]) == 28000


@patch("ingestion.graph_sync.cve_cwe_kev._mark_snowflake_synced")
@patch("ingestion.graph_sync.cve_cwe_kev._neo4j_write_transaction")
@patch("ingestion.graph_sync.cve_cwe_kev._fetch_cwe_rows")
@patch("ingestion.graph_sync.cve_cwe_kev._fetch_mappings_for_cves")
@patch("ingestion.graph_sync.cve_cwe_kev._fetch_cve_rows")
@patch("ingestion.graph_sync.cve_cwe_kev._fetch_cve_id_batch")
@patch("ingestion.graph_sync.cve_cwe_kev._ensure_constraints")
def test_run_cve_cwe_kev_sync_one_batch(
    mock_constraints,
    mock_ids,
    mock_cves,
    mock_maps,
    mock_cwes,
    mock_neo_tx,
    mock_mark,
):
    mock_ids.side_effect = [
        ["CVE-2024-0001"],
        [],
    ]
    mock_cves.return_value = [
        {
            "cve_id": "CVE-2024-0001",
            "published_date": None,
            "last_modified": None,
            "vuln_status": "Analyzed",
            "description_en": "d",
            "cvss_version": "3.1",
            "cvss_score": 7.0,
            "cvss_severity": "HIGH",
            "attack_vector": None,
            "attack_complexity": None,
            "privileges_required": None,
            "user_interaction": None,
            "scope": None,
            "confidentiality_impact": None,
            "integrity_impact": None,
            "has_exploit_ref": False,
            "is_kev": True,
            "kev_date_added": None,
            "kev_ransomware_use": None,
            "kev_required_action": None,
            "kev_due_date": None,
            "kev_vendor_project": None,
            "kev_product": None,
        }
    ]
    mock_maps.return_value = [
        {
            "mapping_id": "CVE-2024-0001|CWE-79|nvd",
            "cve_id": "CVE-2024-0001",
            "cwe_id": "CWE-79",
            "mapping_source": "nvd",
            "mapping_type": "PrimaryOrSecondary",
        }
    ]
    mock_cwes.return_value = [
        {
            "cwe_id": "CWE-79",
            "name": "XSS",
            "abstraction": "Base",
            "status": "Stable",
            "is_deprecated": False,
        }
    ]

    stats = run_cve_cwe_kev_sync(batch_size=50, full=False, max_batches=5)

    assert stats["batches"] == 1
    assert stats["cves_processed"] == 1
    assert stats["cwes_touched"] == 1
    assert stats["relationships_merged"] == 1
    mock_neo_tx.assert_called_once()
    mock_mark.assert_called_once()
    cve_ids, map_ids, cwe_ids = mock_mark.call_args[0]
    assert cve_ids == ["CVE-2024-0001"]
    assert "CVE-2024-0001|CWE-79|nvd" in map_ids
    assert "CWE-79" in cwe_ids
