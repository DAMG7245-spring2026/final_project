"""Transform MITRE ATT&CK STIX objects into Snowflake row dicts."""

from __future__ import annotations

from typing import Any


def resolve_subtechnique_parents(
    relationships: list[dict[str, Any]],
    mitre_id_lookup: dict[str, str],
) -> dict[str, str]:
    """Build child technique STIX ID -> parent ATT&CK ID map."""
    parent_map: dict[str, str] = {}
    for rel in relationships:
        if rel.get("relationship_type") != "subtechnique-of":
            continue
        child_stix = rel.get("source_ref", "")
        parent_stix = rel.get("target_ref", "")
        parent_mitre = mitre_id_lookup.get(parent_stix)
        if child_stix and parent_mitre:
            parent_map[child_stix] = parent_mitre
    return parent_map


def transform_technique(obj: dict[str, Any], parent_map: dict[str, str]) -> dict[str, Any]:
    phases = obj.get("kill_chain_phases", [])
    tactic = phases[0]["phase_name"] if phases else None
    stix_id = obj["id"]
    return {
        "mitre_id": obj.get("x_mitre_id") or _external_id(obj),
        "stix_id": stix_id,
        "name": obj.get("name"),
        "tactic": tactic,
        "description": (obj.get("description", "") or "")[:4000],
        "platforms": obj.get("x_mitre_platforms", []),
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
        "parent_id": parent_map.get(stix_id),
        "is_deprecated": bool(obj.get("x_mitre_deprecated", False)),
        "is_revoked": bool(obj.get("revoked", False)),
        "mitre_version": obj.get("x_mitre_version"),
    }


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def transform_actor(obj: dict[str, Any]) -> dict[str, Any]:
    motivations = obj.get("primary_motivation", [])
    return {
        "actor_name": obj.get("name"),
        "stix_id": obj.get("id"),
        "external_id": _external_id(obj),
        "aliases": obj.get("aliases", []),
        "country": None,
        "motivation": motivations[0] if motivations else None,
        "description": (obj.get("description", "") or "")[:4000],
        "target_sectors": [],
    }


def transform_mitigation(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "mitigation_id": _external_id(obj),
        "stix_id": obj.get("id"),
        "name": obj.get("name"),
        "description": (obj.get("description", "") or "")[:4000],
    }


def transform_tactic(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "tactic_id": _external_id(obj),
        "stix_id": obj.get("id"),
        "name": obj.get("name"),
        "shortname": obj.get("x_mitre_shortname"),
        "description": (obj.get("description", "") or "")[:4000],
        "tactic_order": None,
    }


def transform_campaign(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "campaign_id": _external_id(obj) or obj.get("id"),
        "stix_id": obj.get("id"),
        "external_id": _external_id(obj),
        "name": obj.get("name"),
        "description": (obj.get("description", "") or "")[:4000],
    }


def transform_relationship(
    obj: dict[str, Any],
    lookup: dict[str, str],
) -> dict[str, Any] | None:
    source_stix = obj.get("source_ref", "")
    target_stix = obj.get("target_ref", "")
    source_name = lookup.get(source_stix)
    target_name = lookup.get(target_stix)
    if not source_name or not target_name:
        return None
    return {
        "relationship_id": f"{source_stix}_{target_stix}_{obj.get('relationship_type', '')}",
        "source_stix_id": source_stix,
        "source_name": source_name,
        "source_type": source_stix.split("--")[0].replace("-", "_"),
        "target_stix_id": target_stix,
        "target_name": target_name,
        "target_type": target_stix.split("--")[0].replace("-", "_"),
        "relation_type": obj.get("relationship_type"),
    }
