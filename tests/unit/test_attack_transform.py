"""Unit tests for ATT&CK transform helpers."""

from ingestion.attack.transform import (
    resolve_subtechnique_parents,
    transform_relationship,
    transform_technique,
)


def test_resolve_subtechnique_parents_maps_child_to_parent_id():
    relationships = [
        {
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--child",
            "target_ref": "attack-pattern--parent",
        }
    ]
    mitre_lookup = {"attack-pattern--parent": "T1000"}
    out = resolve_subtechnique_parents(relationships, mitre_lookup)
    assert out == {"attack-pattern--child": "T1000"}


def test_transform_technique_uses_parent_map():
    obj = {
        "id": "attack-pattern--child",
        "x_mitre_id": "T1000.001",
        "name": "Child Technique",
        "x_mitre_platforms": ["Windows"],
        "x_mitre_is_subtechnique": True,
        "kill_chain_phases": [{"phase_name": "execution"}],
    }
    row = transform_technique(obj, {"attack-pattern--child": "T1000"})
    assert row["mitre_id"] == "T1000.001"
    assert row["parent_id"] == "T1000"
    assert row["tactic"] == "execution"


def test_transform_technique_uses_external_ref_when_x_mitre_id_missing():
    obj = {
        "id": "attack-pattern--child",
        "name": "Child Technique",
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1055.011"}
        ],
    }
    row = transform_technique(obj, {})
    assert row["mitre_id"] == "T1055.011"


def test_transform_relationship_returns_none_when_unmapped():
    rel = {
        "source_ref": "intrusion-set--x",
        "target_ref": "attack-pattern--y",
        "relationship_type": "uses",
    }
    assert transform_relationship(rel, {}) is None
