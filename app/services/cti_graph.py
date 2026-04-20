"""Neo4j read helpers for CTI structured API routes (JSON-safe values)."""

from __future__ import annotations

import re
from datetime import date, datetime, time
from typing import Any

from neo4j.time import Date as Neo4jDate
from neo4j.time import DateTime as Neo4jDateTime
from neo4j.time import Time as Neo4jTime

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
TECHNIQUE_ID_RE = re.compile(r"^T\d{4,5}(?:\.\d{3})?$", re.IGNORECASE)


def normalize_cve_id(cve_id: str) -> str:
    return cve_id.strip().upper()


def normalize_technique_id(tech_id: str) -> str:
    s = tech_id.strip().upper()
    return s


def is_valid_cve_id(cve_id: str) -> bool:
    return bool(CVE_ID_RE.match(normalize_cve_id(cve_id)))


def is_valid_technique_id(tech_id: str) -> bool:
    return bool(TECHNIQUE_ID_RE.match(normalize_technique_id(tech_id)))


def neo4j_value_to_json(value: Any) -> Any:
    """Convert Neo4j driver / temporal types to JSON-serializable Python values."""
    if value is None:
        return None
    if isinstance(value, (Neo4jDateTime, Neo4jDate, Neo4jTime)):
        return str(value)
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, list):
        return [neo4j_value_to_json(v) for v in value]
    if isinstance(value, dict):
        return {k: neo4j_value_to_json(v) for k, v in value.items()}
    return value


def _nodeish_to_dict(obj: Any) -> dict[str, Any] | None:
    if obj is None:
        return None
    if hasattr(obj, "labels") and hasattr(obj, "items"):
        return {
            "labels": list(obj.labels),
            "properties": neo4j_value_to_json(dict(obj)),
        }
    return None


def serialize_execute_result(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Walk result rows and convert Neo4j Node/Relationship/path types."""
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append({k: _serialize_cell(v) for k, v in row.items()})
    return out


def _serialize_cell(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "labels") and hasattr(value, "items"):
        return _nodeish_to_dict(value)
    if hasattr(value, "type") and hasattr(value, "items") and callable(getattr(value, "type", None)):
        try:
            return {
                "type": value.type,
                "properties": neo4j_value_to_json(dict(value.items())),
            }
        except Exception:
            return str(value)
    if isinstance(value, list):
        return [_serialize_cell(v) for v in value]
    if isinstance(value, dict):
        return {k: _serialize_cell(v) for k, v in value.items()}
    return neo4j_value_to_json(value)


def cve_properties_cypher(cve_id: str) -> tuple[str, dict[str, Any]]:
    return "MATCH (c:CVE {id: $id}) RETURN properties(c) AS cve", {"id": cve_id}


def cve_weaknesses_cypher(cve_id: str) -> tuple[str, dict[str, Any]]:
    q = """
    MATCH (c:CVE {id: $id})-[r:HAS_WEAKNESS]->(w:CWE)
    RETURN w.id AS cwe_id, properties(w) AS cwe, properties(r) AS rel_props
    """
    return q, {"id": cve_id}


def cve_technique_refs_cypher(cve_id: str) -> tuple[str, dict[str, Any]]:
    q = """
    MATCH (c:CVE {id: $id})-[r:REFERENCES_TECHNIQUE]->(t:Technique)
    RETURN t.id AS technique_id, properties(t) AS technique, properties(r) AS rel_props
    """
    return q, {"id": cve_id}


def cve_exists_cypher(cve_id: str) -> tuple[str, dict[str, Any]]:
    return "MATCH (c:CVE {id: $id}) RETURN count(c) AS n", {"id": cve_id}


def technique_exists_cypher(technique_id: str) -> tuple[str, dict[str, Any]]:
    return "MATCH (t:Technique {id: $id}) RETURN count(t) AS n", {"id": technique_id}


def actor_exists_cypher(actor_id: str) -> tuple[str, dict[str, Any]]:
    q = """
    MATCH (a:Actor)
    WHERE coalesce(a.name, '') = $id
       OR coalesce(a.actor_id, '') = $id
       OR coalesce(a.id, '') = $id
       OR coalesce(a.external_id, '') = $id
    RETURN count(a) AS n
    """
    return q, {"id": actor_id}


def actor_detail_cypher(actor_id: str) -> tuple[str, dict[str, Any]]:
    q = """
    MATCH (a:Actor)
    WHERE coalesce(a.name, '') = $id
       OR coalesce(a.actor_id, '') = $id
       OR coalesce(a.id, '') = $id
       OR coalesce(a.external_id, '') = $id
    WITH a LIMIT 1
    RETURN properties(a) AS actor,
      [(a)-[r]-(n) | {
        rel_type: type(r),
        rel_props: properties(r),
        neighbor_labels: labels(n),
        neighbor_props: properties(n)
      }][0..80] AS edges
    """
    return q, {"id": actor_id}


def technique_detail_cypher(technique_id: str) -> tuple[str, dict[str, Any]]:
    q = """
    MATCH (t:Technique {id: $id})
    RETURN properties(t) AS technique,
      [(t)-[r]-(n) | {
        rel_type: type(r),
        rel_props: properties(r),
        neighbor_labels: labels(n),
        neighbor_props: properties(n)
      }][0..80] AS edges
    """
    return q, {"id": technique_id}


def _clamp_hops_limit(max_hops: int, limit: int) -> tuple[int, int]:
    mh = max(1, min(int(max_hops), 6))
    lim = max(1, min(int(limit), 25))
    return mh, lim


def attack_paths_cypher(
    *,
    kind: str,
    value: str,
    max_hops: int,
    limit: int,
) -> tuple[str, dict[str, Any]]:
    """
    Bounded variable-length paths from a CVE, Actor, or Technique start node.
    kind must be 'cve', 'actor', or 'technique' (validated by caller).
    """
    mh, lim = _clamp_hops_limit(max_hops, limit)
    kind_l = kind.strip().lower()
    if kind_l == "cve":
        start_match = """
        MATCH (start:CVE {id: $val})
        WHERE coalesce(start.vuln_status, '') <> 'Deferred'
        """
        # published_date is stored as ISO string from sync (_iso), not a native date;
        # use date() for compare. NULL vuln_status / published_date: treat as non-blocking.
        path_where = """
        WHERE NOT end:CVE
          AND ALL(n IN nodes(p) WHERE
              NOT n:CVE
              OR (coalesce(n.vuln_status, '') <> 'Deferred'
                  AND (n.published_date IS NULL
                       OR date(n.published_date) >= date('2015-01-01'))))
        """
    elif kind_l == "technique":
        start_match = "MATCH (start:Technique {id: $val})"
        path_where = "WHERE NOT end:Technique"
    elif kind_l == "actor":
        start_match = """
        MATCH (start:Actor)
        WHERE coalesce(start.name, '') = $val
           OR coalesce(start.actor_id, '') = $val
           OR coalesce(start.id, '') = $val
           OR coalesce(start.external_id, '') = $val
        """
        path_where = "WHERE NOT end:Actor"
    else:
        raise ValueError(f"invalid attack path kind: {kind}")

    q = f"""
    {start_match}
    MATCH p = (start)-[*1..{mh}]->(end)
    {path_where}
    WITH p LIMIT {lim}
    RETURN collect({{
      nodes: [n IN nodes(p) | {{labels: labels(n), properties: properties(n)}}],
      rels: [r IN relationships(p) | {{type: type(r), properties: properties(r)}}]
    }}) AS paths
    """
    return q, {"val": value}
