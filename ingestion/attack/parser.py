"""Fetch and preprocess MITRE ATT&CK STIX bundle."""

from __future__ import annotations

from typing import Any

import httpx

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)

def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def fetch_attack_bundle(client: httpx.Client | None = None) -> list[dict[str, Any]]:
    """Download full ATT&CK Enterprise STIX bundle and return ``objects``."""
    own_client = client is None
    if client is None:
        client = httpx.Client(timeout=120.0, follow_redirects=True)
    try:
        r = client.get(ATTACK_URL)
        r.raise_for_status()
        bundle = r.json()
        return bundle.get("objects", [])
    finally:
        if own_client:
            client.close()


def build_stix_lookup(objects: list[dict[str, Any]]) -> dict[str, str]:
    """Map STIX ID to a readable ATT&CK identifier or name."""
    lookup: dict[str, str] = {}
    for obj in objects:
        stix_id = obj.get("id", "")
        t = obj.get("type")
        if not stix_id or not t:
            continue
        if t == "attack-pattern":
            lookup[stix_id] = obj.get("x_mitre_id") or _external_id(obj) or obj.get("name", "")
        elif t == "intrusion-set":
            lookup[stix_id] = obj.get("name", "")
        elif t == "course-of-action":
            lookup[stix_id] = obj.get("x_mitre_id") or _external_id(obj) or obj.get("name", "")
        elif t == "x-mitre-tactic":
            lookup[stix_id] = obj.get("x_mitre_shortname", obj.get("name", ""))
        elif t in ("malware", "tool", "campaign"):
            lookup[stix_id] = obj.get("name", "")
    return lookup


def build_mitre_id_lookup(objects: list[dict[str, Any]]) -> dict[str, str]:
    """Map technique STIX ID to ATT&CK external ID (e.g. T1059.001)."""
    out: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        mid = obj.get("x_mitre_id") or _external_id(obj)
        if mid:
            out[obj["id"]] = mid
    return out


def filter_objects(objects: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Split bundle into typed lists while skipping revoked/deprecated entries."""
    out: dict[str, list[dict[str, Any]]] = {
        "techniques": [],
        "actors": [],
        "mitigations": [],
        "tactics": [],
        "campaigns": [],
        "relationships": [],
    }
    for obj in objects:
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        t = obj.get("type")
        if t == "attack-pattern":
            out["techniques"].append(obj)
        elif t == "intrusion-set":
            out["actors"].append(obj)
        elif t == "course-of-action":
            out["mitigations"].append(obj)
        elif t == "x-mitre-tactic":
            out["tactics"].append(obj)
        elif t == "campaign":
            out["campaigns"].append(obj)
        elif t == "relationship":
            out["relationships"].append(obj)
    return out
