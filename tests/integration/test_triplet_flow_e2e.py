"""Validate that the persisted triplet pipeline is self-consistent.

Treats ``extracted_triplets`` (Phase 1/2 output) and the Neo4j graph
(Phase 4 output) as the ground truth and checks three invariants the
loader promises:

  1. Every relation type that appears in the triplet table also appears
     in Neo4j under the expected Cypher label for this advisory. Missing
     labels mean Phase 4 silently dropped some classifications.

  2. Neo4j never has MORE edges of a given relation than the triplet table
     has triplets — MERGE is supposed to dedupe. Inequality the other way
     would signal an idempotency regression.

  3. For every individual triplet, there exists a matching edge with the
     right ``advisory_id``. Sampled rather than exhaustive to keep Neo4j
     load low, but we verify the known-strong one (first ``exploits``
     triplet of the advisory) explicitly.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def _triplets_for_advisory(sf, advisory_id: str) -> list[dict]:
    return sf.execute_query(
        "SELECT subject, relation, object FROM extracted_triplets "
        "WHERE advisory_id = %s",
        (advisory_id,),
    )


def test_every_relation_type_in_triplets_appears_in_neo4j(ground_truth_advisory):
    """All relation labels seen in extracted_triplets must be represented
    by at least one edge in Neo4j for the same advisory. Catches silent
    drops in Phase 4 entity classification (e.g. a whole relation type
    being thrown away because of an unmapped entity type)."""
    from app.services.snowflake import get_snowflake_service
    from app.services.neo4j_service import get_neo4j_service
    from ingestion.advisory.triplets import RELATION_MAP

    sf = get_snowflake_service()
    neo = get_neo4j_service()
    aid = ground_truth_advisory["advisory_id"]

    triplets = _triplets_for_advisory(sf, aid)
    assert triplets, f"ground-truth advisory {aid} has zero triplets persisted"

    # Collapse triplets to the set of Cypher relation labels they'd produce.
    expected_labels = {
        RELATION_MAP.get(t["relation"], t["relation"].upper())
        for t in triplets
    }

    edge_rows = neo.execute_query(
        "MATCH ()-[r]->() WHERE r.advisory_id = $aid "
        "RETURN type(r) AS rel, count(*) AS c",
        {"aid": aid},
    )
    present_labels = {r["rel"] for r in edge_rows}

    missing = expected_labels - present_labels
    assert not missing, (
        f"Neo4j missing edge labels for {aid}: {missing}. "
        f"Triplets have {sorted(expected_labels)}, graph has {sorted(present_labels)}."
    )


def test_neo4j_edge_counts_never_exceed_triplet_counts(ground_truth_advisory):
    """MERGE-on (s, rel, o, advisory_id) means edges ≤ triplets per relation."""
    from app.services.snowflake import get_snowflake_service
    from app.services.neo4j_service import get_neo4j_service
    from ingestion.advisory.triplets import RELATION_MAP

    sf = get_snowflake_service()
    neo = get_neo4j_service()
    aid = ground_truth_advisory["advisory_id"]

    triplets = _triplets_for_advisory(sf, aid)
    triplets_by_label: dict[str, int] = {}
    for t in triplets:
        label = RELATION_MAP.get(t["relation"], t["relation"].upper())
        triplets_by_label[label] = triplets_by_label.get(label, 0) + 1

    edge_rows = neo.execute_query(
        "MATCH ()-[r]->() WHERE r.advisory_id = $aid "
        "RETURN type(r) AS rel, count(*) AS c",
        {"aid": aid},
    )
    edges_by_label = {r["rel"]: r["c"] for r in edge_rows}

    bad = {
        rel: (edges_by_label[rel], triplets_by_label[rel])
        for rel in edges_by_label
        if edges_by_label[rel] > triplets_by_label.get(rel, 0)
    }
    assert not bad, (
        f"Neo4j has more edges than triplets for {aid}: "
        f"{bad} (format: rel -> (edges, triplets)). Idempotency broken?"
    )


def test_sampled_triplet_has_matching_neo4j_edge(ground_truth_advisory):
    """For one concrete triplet, verify the round-trip: the exact
    (subject, relation, object, advisory_id) tuple must resolve to a real
    edge in Neo4j. We pick the first 'exploits' triplet because the CVE
    target has a known Cypher-visible shape (CVE node matched by id)."""
    from app.services.snowflake import get_snowflake_service
    from app.services.neo4j_service import get_neo4j_service

    sf = get_snowflake_service()
    neo = get_neo4j_service()
    aid = ground_truth_advisory["advisory_id"]

    candidates = sf.execute_query(
        "SELECT subject, relation, object FROM extracted_triplets "
        "WHERE advisory_id = %s AND relation = 'exploits' "
        "ORDER BY triplet_id LIMIT 1",
        (aid,),
    )
    if not candidates:
        pytest.skip(f"{aid} has no 'exploits' triplets to sample")

    sample = candidates[0]
    subject, cve_id = sample["subject"], sample["object"]

    rows = neo.execute_query(
        "MATCH (s)-[r:EXPLOITS]->(c:CVE {id: $cve}) "
        "WHERE r.advisory_id = $aid AND coalesce(s.name, s.id) = $subj "
        "RETURN r.is_inferred AS inferred LIMIT 1",
        {"aid": aid, "cve": cve_id, "subj": subject},
    )
    assert rows, (
        f"Triplet claims {subject!r} EXPLOITS {cve_id!r} in {aid}, "
        "but no matching edge is in Neo4j"
    )


def test_entity_aliases_are_applied_to_triplet_table(ground_truth_advisory):
    """After Phase 2, ``extracted_triplets.subject`` / ``object`` must
    never hold an alias form that is substantively different from its
    canonical. Matches where alias and canonical differ only by case
    (e.g. alias='Plink', canonical='PLINK') don't count as leaks — the
    stored value is already case-equivalent to the canonical."""
    from app.services.snowflake import get_snowflake_service
    sf = get_snowflake_service()
    aid = ground_truth_advisory["advisory_id"]

    leaking = sf.execute_query(
        """
        SELECT t.triplet_id, t.subject, t.object, ea.alias_name, ea.canonical_name
        FROM extracted_triplets t
        JOIN entity_aliases ea
          ON (LOWER(t.subject) = LOWER(ea.alias_name)
              AND LOWER(t.subject) != LOWER(ea.canonical_name))
          OR (LOWER(t.object) = LOWER(ea.alias_name)
              AND LOWER(t.object) != LOWER(ea.canonical_name))
        WHERE t.advisory_id = %s
        """,
        (aid,),
    )
    assert not leaking, (
        f"alias names still present in extracted_triplets for {aid}: {leaking}"
    )
