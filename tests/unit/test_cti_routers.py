"""Unit tests for CTI structured API routes (Neo4j mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def client():
    return TestClient(create_app())


def test_query_stub(client: TestClient):
    r = client.post("/query", json={"query": "What exploits CVE-2024-1?"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending"
    assert "Neo4j" in body["message"] or "Advisory" in body["message"]


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
