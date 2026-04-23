"""Graph query integration tests.

Loads a known subgraph into the real Neo4j instance (using _test=true marker
so teardown can delete exactly those nodes/edges), then verifies the five core
Cypher query patterns used by the Text2Cypher synthesis agent return the
correct structure and non-empty results.

Run with:
    poetry run pytest tests/integration/test_graph_query_integration.py -v

Requires: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD in environment / .env
"""
import pytest
from dotenv import load_dotenv

load_dotenv()

from app.services.neo4j_service import get_neo4j_service  # noqa: E402

# ── Test subgraph ─────────────────────────────────────────────────────────────
# All test nodes carry `_test: true` so the cleanup query can remove them
# precisely without touching real graph data.

SEED_CYPHER = """
MERGE (a:Actor    {name: '__TestActor',     _test: true})
MERGE (m:Malware  {name: '__TestMalware',   _test: true})
MERGE (t:Technique{name: '__TestTechnique', _test: true})
MERGE (o:Other    {name: '__TestTool',      _test: true})
MERGE (c:CVE      {id:   'CVE-9999-0001',   is_kev: true,  description_en: 'Test CVE', _test: true})
MERGE (a)-[:USES     {advisory_id: 'test-adv', is_inferred: false}]->(m)
MERGE (a)-[:USES     {advisory_id: 'test-adv', is_inferred: false}]->(t)
MERGE (a)-[:USES     {advisory_id: 'test-adv', is_inferred: false}]->(o)
MERGE (a)-[:EXPLOITS {advisory_id: 'test-adv', is_inferred: false}]->(c)
MERGE (m)-[:EXPLOITS {advisory_id: 'test-adv', is_inferred: false}]->(c)
"""

CLEANUP_CYPHER = "MATCH (n {_test: true}) DETACH DELETE n"


@pytest.fixture(scope="module", autouse=True)
def seed_and_cleanup():
    svc = get_neo4j_service()
    svc.execute_write(SEED_CYPHER)
    yield
    svc.execute_write(CLEANUP_CYPHER)


# ── Helper ────────────────────────────────────────────────────────────────────

def neo4j():
    return get_neo4j_service()


# ── Query 1: Actor -[USES]-> Malware (Example 1 in FEW_SHOT_EXAMPLES) ─────────

def test_actor_uses_malware_returns_rows_and_advisory_id():
    rows = neo4j().execute_query("""
        MATCH (a:Actor)-[r:USES]->(m:Malware)
        WHERE toLower(a.name) CONTAINS toLower('__TestActor')
        RETURN a.name, m.name, r.advisory_id
        LIMIT 50
    """)
    assert len(rows) >= 1, "Expected at least one USES→Malware edge"
    row = rows[0]
    assert "a.name" in row
    assert "m.name" in row
    assert "r.advisory_id" in row
    assert row["r.advisory_id"] == "test-adv"


# ── Query 2: USES polymorphic — Malware / Technique / Other (Example 2) ───────

def test_uses_polymorphic_returns_all_three_target_types():
    rows = neo4j().execute_query("""
        MATCH (a:Actor)-[r:USES]->(n)
        WHERE toLower(a.name) CONTAINS toLower('__TestActor')
          AND (n:Malware OR n:Technique OR n:Other)
        RETURN a.name, labels(n)[0] AS target_type, n.name, r.advisory_id
        LIMIT 50
    """)
    assert len(rows) >= 3, "Expected edges to Malware, Technique, and Other"
    target_types = {r["target_type"] for r in rows}
    assert "Malware" in target_types
    assert "Technique" in target_types
    assert "Other" in target_types
    for row in rows:
        assert "r.advisory_id" in row


# ── Query 3: Malware -[EXPLOITS]-> CVE with description (Example 3) ───────────

def test_malware_exploits_cve_returns_description_and_kev_flag():
    rows = neo4j().execute_query("""
        MATCH (m:Malware)-[r:EXPLOITS]->(c:CVE)
        WHERE toLower(m.name) CONTAINS toLower('__TestMalware')
        RETURN m.name, c.id, c.description_en, c.is_kev, r.advisory_id
        LIMIT 50
    """)
    assert len(rows) >= 1, "Expected at least one EXPLOITS edge from Malware to CVE"
    row = rows[0]
    assert row["c.id"] == "CVE-9999-0001"
    assert "c.description_en" in row
    assert "c.is_kev" in row
    assert "r.advisory_id" in row


# ── Query 4: count(Actor) aggregation — no LIMIT (Example 4) ─────────────────

def test_actor_count_aggregation_returns_nonzero():
    rows = neo4j().execute_query(
        "MATCH (a:Actor) RETURN count(a) AS actor_count"
    )
    assert len(rows) == 1, "Aggregation must return exactly one row"
    assert "actor_count" in rows[0]
    assert rows[0]["actor_count"] >= 1


# ── Query 5: KEV CVEs linked to actor (Example 5) ────────────────────────────

def test_kev_cve_linked_to_actor_returns_advisory_id():
    rows = neo4j().execute_query("""
        MATCH (a:Actor)-[r:EXPLOITS]->(c:CVE)
        WHERE c.is_kev = true
          AND toLower(a.name) CONTAINS toLower('__TestActor')
        RETURN a.name, c.id, c.description_en, c.is_kev, r.advisory_id
        LIMIT 50
    """)
    assert len(rows) >= 1, "Expected at least one KEV CVE linked to test actor"
    row = rows[0]
    assert row["c.is_kev"] is True
    assert "r.advisory_id" in row
    assert row["r.advisory_id"] == "test-adv"
