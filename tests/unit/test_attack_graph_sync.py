"""Unit tests for ATT&CK technique and chunk-link Neo4j sync."""

from __future__ import annotations

import sys
import types
from unittest.mock import patch

if "neo4j" not in sys.modules:
    _neo4j_stub = types.ModuleType("neo4j")

    class _GraphDatabase:
        @staticmethod
        def driver(*_a, **_k):
            raise RuntimeError("neo4j driver not configured in this test run")

    _neo4j_stub.GraphDatabase = _GraphDatabase
    _neo4j_stub.Driver = type("Driver", (), {})
    sys.modules["neo4j"] = _neo4j_stub

from ingestion.graph_sync.attack_techniques_sync import (
    _pairs_from_chunk_row,
    _technique_to_neo_row,
    run_attack_techniques_sync,
    run_chunk_technique_link_sync,
)


def test_technique_to_neo_row_truncates_long_description():
    long_desc = "x" * 30000
    row = _technique_to_neo_row(
        {
            "mitre_id": "T1059",
            "name": "CLI",
            "tactic": "Execution",
            "description": long_desc,
            "platforms": ["Linux"],
            "is_subtechnique": False,
            "parent_id": None,
            "is_deprecated": False,
            "is_revoked": False,
            "mitre_version": "14",
            "stix_id": "s1",
        }
    )
    assert len(row["description"]) == 28000


def test_pairs_from_chunk_row_filters_and_normalizes():
    row = {
        "cve_ids": ["CVE-2024-2"],
        "mitre_tech_ids": ["t1059", "X123", "T1566.001"],
    }
    pairs = _pairs_from_chunk_row(row)
    assert set(pairs) == {
        ("CVE-2024-2", "T1059"),
        ("CVE-2024-2", "T1566.001"),
    }


@patch("ingestion.graph_sync.attack_techniques_sync._mark_techniques_synced")
@patch("ingestion.graph_sync.attack_techniques_sync._neo4j_write_transaction")
@patch("ingestion.graph_sync.attack_techniques_sync._fetch_technique_batch")
def test_run_attack_techniques_sync_one_batch(mock_fetch, mock_neo, mock_mark):
    mock_fetch.side_effect = [
        [
            {
                "mitre_id": "T1059",
                "stix_id": "s",
                "name": "n",
                "tactic": "t",
                "description": "d",
                "platforms": None,
                "is_subtechnique": False,
                "parent_id": None,
                "is_deprecated": False,
                "is_revoked": False,
                "mitre_version": "14",
            }
        ],
        [],
    ]

    stats = run_attack_techniques_sync(
        batch_size=50, full=False, neo4j_database=None, max_batches=5
    )

    assert stats["batches"] == 1
    assert stats["techniques_merged"] == 1
    assert mock_neo.call_count == 2
    mock_mark.assert_called_once_with(["T1059"])


@patch("ingestion.graph_sync.attack_techniques_sync._neo4j_write_transaction")
@patch("ingestion.graph_sync.attack_techniques_sync._fetch_chunk_batch")
def test_run_chunk_technique_link_sync_dedupes_across_batches(mock_fetch, mock_neo):
    mock_fetch.side_effect = [
        [
            {
                "chunk_id": "a",
                "cve_ids": ["CVE-2024-1"],
                "mitre_tech_ids": ["T1059"],
            }
        ],
        [
            {
                "chunk_id": "b",
                "cve_ids": ["CVE-2024-1"],
                "mitre_tech_ids": ["T1059"],
            }
        ],
        [],
    ]

    stats = run_chunk_technique_link_sync(
        batch_size=10, neo4j_database=None, max_batches=10
    )

    assert stats["batches"] == 2
    assert stats["unique_pairs_merged"] == 1
    assert mock_neo.call_count == 1


@patch("ingestion.graph_sync.attack_techniques_sync._neo4j_write_transaction")
@patch("ingestion.graph_sync.attack_techniques_sync._fetch_chunk_batch")
def test_run_chunk_technique_link_sync_skips_neo_when_no_valid_pairs(mock_fetch, mock_neo):
    mock_fetch.side_effect = [
        [{"chunk_id": "x", "cve_ids": [], "mitre_tech_ids": ["T1059"]}],
        [],
    ]

    stats = run_chunk_technique_link_sync(batch_size=10, max_batches=5)

    assert stats["batches"] == 1
    assert stats["unique_pairs_merged"] == 0
    assert mock_neo.call_count == 0
