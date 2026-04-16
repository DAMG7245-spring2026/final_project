"""Unit tests for ATT&CK Snowflake loader."""

from unittest.mock import MagicMock, patch

from ingestion.attack.loader import upsert_all_attack_tables


def test_upsert_all_attack_tables_executes_expected_groups():
    mock_cur = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value = mock_cur
    mock_sf = MagicMock()
    mock_sf.cursor.return_value = mock_ctx

    techniques = [
        {
            "mitre_id": "T1001",
            "stix_id": "attack-pattern--1",
            "name": "Technique",
            "tactic": "execution",
            "description": "d",
            "platforms": ["Windows"],
            "is_subtechnique": False,
            "parent_id": None,
            "is_deprecated": False,
            "is_revoked": False,
            "mitre_version": "1.0",
        }
    ]
    actors = [
        {
            "actor_name": "APT1",
            "stix_id": "intrusion-set--1",
            "external_id": "G0001",
            "aliases": [],
            "country": None,
            "motivation": None,
            "description": "d",
            "target_sectors": [],
        }
    ]
    relationships = [
        {
            "relationship_id": "a_b_uses",
            "source_stix_id": "a",
            "source_name": "APT1",
            "source_type": "intrusion_set",
            "target_stix_id": "b",
            "target_name": "T1001",
            "target_type": "attack_pattern",
            "relation_type": "uses",
        }
    ]
    with patch("ingestion.attack.loader.get_snowflake_service", return_value=mock_sf):
        stats = upsert_all_attack_tables(
            techniques=techniques,
            actors=actors,
            mitigations=[],
            tactics=[],
            campaigns=[],
            relationships=relationships,
        )
    assert stats["techniques"] == 1
    assert stats["actors"] == 1
    assert stats["relationships"] == 1
    sqls = [c.args[0] for c in mock_cur.execute.call_args_list]
    assert any("CREATE TEMP TABLE IF NOT EXISTS attack_techniques_staging" in s for s in sqls)
    assert any("CREATE TEMP STAGE IF NOT EXISTS attack_techniques_stage" in s for s in sqls)
    assert any("PUT 'file://" in s and "@attack_techniques_stage/" in s for s in sqls)
    assert any("COPY INTO attack_techniques_staging" in s for s in sqls)
    assert any("MERGE INTO attack_techniques AS t" in s for s in sqls)
    assert any("MERGE INTO attack_actors AS t" in s for s in sqls)
    assert any("MERGE INTO attack_relationships AS t" in s for s in sqls)
