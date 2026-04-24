"""Snowflake to Neo4j structured graph sync."""

from __future__ import annotations

from typing import Any

__all__ = [
    "run_attack_techniques_sync",
    "run_chunk_technique_link_sync",
    "run_cve_cwe_kev_sync",
    "run_sync_kev_neo4j",
]


def __getattr__(name: str) -> Any:
    """Lazy imports so ``from ingestion.graph_sync.kev_neo4j_sync import ...`` does not load ATT&CK sync."""
    if name == "run_attack_techniques_sync":
        from ingestion.graph_sync.attack_techniques_sync import run_attack_techniques_sync

        return run_attack_techniques_sync
    if name == "run_chunk_technique_link_sync":
        from ingestion.graph_sync.attack_techniques_sync import run_chunk_technique_link_sync

        return run_chunk_technique_link_sync
    if name == "run_cve_cwe_kev_sync":
        from ingestion.graph_sync.cve_cwe_kev import run_cve_cwe_kev_sync

        return run_cve_cwe_kev_sync
    if name == "run_sync_kev_neo4j":
        from ingestion.graph_sync.kev_neo4j_sync import run_sync_kev_neo4j

        return run_sync_kev_neo4j
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
