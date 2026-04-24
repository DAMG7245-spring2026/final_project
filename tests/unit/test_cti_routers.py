"""Unit tests for CTI structured API routes (Neo4j mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def client():
    return TestClient(create_app())


@patch("app.routers.query.get_rag_router_service")
def test_query_stub(mock_get_router, client: TestClient):
    router = MagicMock()
    mock_get_router.return_value = router
    router.answer.return_value = {
        "answer": "Stub answer for demo.",
        "route": "text",
        "route_reasoning": "unit test",
        "route_was_forced": False,
        "fallback_triggered": False,
        "cypher": None,
        "graph_row_count": None,
        "graph_results": None,
        "chunks": [],
    }
    r = client.post("/query", json={"question": "What exploits CVE-2024-1?"})
    assert r.status_code == 200
    body = r.json()
    assert body["answer"] == "Stub answer for demo."
    assert body["route"] == "text"
    router.answer.assert_called_once()


def test_brief_weekly_stub(client: TestClient):
    r = client.get("/brief/weekly")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending"


@patch("app.routers.cve.get_neo4j_service")
def test_get_cve_success(mock_get_neo, client: TestClient):
    neo = MagicMock()
    mock_get_neo.return_value = neo

    def eq(q: str, _p: dict | None = None):
        if "count(c)" in q or "count(c) AS n" in q:
            return [{"n": 1}]
        if "RETURN properties(c) AS cve" in q:
            return [{"cve": {"id": "CVE-2024-0001", "cvss_score": 9.0}}]
        if "HAS_WEAKNESS" in q and "RETURN w.id" in q:
            return [{"cwe_id": "CWE-79", "cwe": {"name": "XSS"}, "rel_props": {}}]
        if "REFERENCES_TECHNIQUE" in q:
            return []
        return []

    neo.execute_query.side_effect = eq
    r = client.get("/cve/CVE-2024-0001")
    assert r.status_code == 200
    data = r.json()
    assert data["cve_id"] == "CVE-2024-0001"
    assert data["cve"]["id"] == "CVE-2024-0001"
    assert len(data["weaknesses"]) == 1


@patch("app.routers.cve.get_neo4j_service")
def test_get_cve_not_found(mock_get_neo, client: TestClient):
    neo = MagicMock()
    mock_get_neo.return_value = neo
    neo.execute_query.return_value = [{"n": 0}]
    r = client.get("/cve/CVE-2024-9999")
    assert r.status_code == 404


def test_get_cve_invalid(client: TestClient):
    r = client.get("/cve/not-a-cve")
    assert r.status_code == 400


@patch("app.routers.graph_attack_path.get_neo4j_service")
def test_attack_path_bad_params(mock_get_neo, client: TestClient):
    r = client.get("/graph/attack-path")
    assert r.status_code == 400
    r = client.get("/graph/attack-path", params={"from_cve": "CVE-2024-1", "from_actor": "X"})
    assert r.status_code == 400


@patch("app.routers.graph_attack_path.get_neo4j_service")
def test_attack_path_not_found(mock_get_neo, client: TestClient):
    neo = MagicMock()
    mock_get_neo.return_value = neo
    neo.execute_query.return_value = [{"n": 0}]
    r = client.get("/graph/attack-path", params={"from_cve": "CVE-2024-0001"})
    assert r.status_code == 404


@patch("app.routers.graph_attack_path.get_neo4j_service")
def test_list_graph_actors(mock_get_neo, client: TestClient):
    neo = MagicMock()
    mock_get_neo.return_value = neo
    neo.execute_query.return_value = [
        {"value": "APT28", "display_name": "APT28", "actor_id": "G0007"},
        {"value": "Lazarus Group", "display_name": "Lazarus Group", "actor_id": ""},
    ]
    r = client.get("/graph/actors")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert len(body["actors"]) == 2
    assert body["actors"][0]["value"] == "APT28"
    assert body["actors"][0]["actor_id"] == "G0007"


@patch("app.routers.metrics.overview_counts")
def test_metrics_overview(mock_overview, client: TestClient):
    mock_overview.return_value = {
        "total_cves_ingested": 1200,
        "kev_flagged": 95,
        "attack_techniques_loaded": 312,
        "advisories_indexed": 410,
    }
    r = client.get("/metrics/overview")
    assert r.status_code == 200
    assert r.json()["kev_flagged"] == 95


@patch("app.routers.metrics.severity_distribution")
def test_metrics_severity_distribution(mock_severity, client: TestClient):
    mock_severity.return_value = [
        {"severity": "CRITICAL", "count": 11},
        {"severity": "HIGH", "count": 20},
    ]
    r = client.get("/metrics/severity-distribution")
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 2
    assert body["items"][0]["severity"] == "CRITICAL"


@patch("app.routers.metrics.recent_pipeline_runs")
def test_metrics_pipeline_runs(mock_runs, client: TestClient):
    mock_runs.return_value = [
        {
            "dag": "nvd_ingest",
            "source": "nvd",
            "status": "success",
            "rows_processed": 450,
            "duration_seconds": 22,
            "timestamp": "2026-04-24T00:00:00",
        }
    ]
    r = client.get("/metrics/pipeline-runs", params={"limit": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["limit"] == 10
    assert body["items"][0]["source"] == "nvd"


def test_attack_paths_cypher_technique_uses_undirected_relationships():
    from app.services.cti_graph import attack_paths_cypher

    q, p = attack_paths_cypher(kind="technique", value="T1059", max_hops=4, limit=10)
    assert p == {"val": "T1059"}
    compact = "".join(q.split())
    assert "OPTIONALMATCHp_long=(start)-[*1..4]-" in compact
    assert "REFERENCES_TECHNIQUE" in compact
    assert "CALL{" not in compact


def test_attack_paths_cypher_cve_stays_outgoing():
    from app.services.cti_graph import attack_paths_cypher

    q, p = attack_paths_cypher(kind="cve", value="CVE-2024-0001", max_hops=3, limit=5)
    assert p == {"val": "CVE-2024-0001"}
    compact = "".join(q.split())
    assert "MATCHp=(start)-[*1..3]->(end)" in compact
