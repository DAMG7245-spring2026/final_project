"""Orchestrate MITRE ATT&CK fetch -> transform -> Snowflake upsert."""

from __future__ import annotations

from typing import Any

from ingestion.attack.loader import upsert_all_attack_tables
from ingestion.attack.parser import (
    build_mitre_id_lookup,
    build_stix_lookup,
    fetch_attack_bundle,
    filter_objects,
)
from ingestion.attack.transform import (
    resolve_subtechnique_parents,
    transform_actor,
    transform_campaign,
    transform_mitigation,
    transform_relationship,
    transform_tactic,
    transform_technique,
)


def run_attack_full_reload() -> dict[str, Any]:
    """Run ATT&CK full refresh and return ingestion stats."""
    objects = fetch_attack_bundle()
    lookup = build_stix_lookup(objects)
    mitre_id_lookup = build_mitre_id_lookup(objects)
    filtered = filter_objects(objects)
    parent_map = resolve_subtechnique_parents(filtered["relationships"], mitre_id_lookup)

    techniques = [
        t
        for o in filtered["techniques"]
        if (t := transform_technique(o, parent_map)).get("mitre_id")
    ]
    actors = [transform_actor(o) for o in filtered["actors"] if o.get("name")]
    mitigations = [
        m for o in filtered["mitigations"] if (m := transform_mitigation(o)).get("mitigation_id")
    ]
    tactics = [t for o in filtered["tactics"] if (t := transform_tactic(o)).get("tactic_id")]
    campaigns = [c for o in filtered["campaigns"] if (c := transform_campaign(o)).get("campaign_id")]
    relationships = [
        r
        for o in filtered["relationships"]
        if (r := transform_relationship(o, lookup)) is not None
    ]

    load_stats = upsert_all_attack_tables(
        techniques=techniques,
        actors=actors,
        mitigations=mitigations,
        tactics=tactics,
        campaigns=campaigns,
        relationships=relationships,
    )
    return {
        "objects_fetched": len(objects),
        "techniques": len(techniques),
        "actors": len(actors),
        "mitigations": len(mitigations),
        "tactics": len(tactics),
        "campaigns": len(campaigns),
        "relationships": len(relationships),
        "load": load_stats,
    }
