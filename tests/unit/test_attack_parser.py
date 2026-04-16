"""Unit tests for ATT&CK parser helpers."""

from ingestion.attack.parser import build_mitre_id_lookup, build_stix_lookup, filter_objects


def test_build_stix_lookup_maps_known_types():
    objects = [
        {"id": "attack-pattern--1", "type": "attack-pattern", "x_mitre_id": "T1001"},
        {"id": "intrusion-set--1", "type": "intrusion-set", "name": "APT1"},
        {"id": "x-mitre-tactic--1", "type": "x-mitre-tactic", "x_mitre_shortname": "initial-access"},
    ]
    lookup = build_stix_lookup(objects)
    assert lookup["attack-pattern--1"] == "T1001"
    assert lookup["intrusion-set--1"] == "APT1"
    assert lookup["x-mitre-tactic--1"] == "initial-access"


def test_build_mitre_id_lookup_only_techniques():
    objects = [
        {"id": "attack-pattern--1", "type": "attack-pattern", "x_mitre_id": "T1001"},
        {"id": "intrusion-set--1", "type": "intrusion-set", "name": "APT1"},
    ]
    out = build_mitre_id_lookup(objects)
    assert out == {"attack-pattern--1": "T1001"}


def test_build_mitre_id_lookup_falls_back_to_external_refs():
    objects = [
        {
            "id": "attack-pattern--1",
            "type": "attack-pattern",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1055.011"}
            ],
        }
    ]
    out = build_mitre_id_lookup(objects)
    assert out == {"attack-pattern--1": "T1055.011"}


def test_filter_objects_skips_deprecated_and_revoked():
    objects = [
        {"type": "attack-pattern", "id": "ok"},
        {"type": "attack-pattern", "id": "deprecated", "x_mitre_deprecated": True},
        {"type": "relationship", "id": "rel-ok"},
        {"type": "relationship", "id": "rel-revoked", "revoked": True},
    ]
    filtered = filter_objects(objects)
    assert len(filtered["techniques"]) == 1
    assert filtered["techniques"][0]["id"] == "ok"
    assert len(filtered["relationships"]) == 1
    assert filtered["relationships"][0]["id"] == "rel-ok"
