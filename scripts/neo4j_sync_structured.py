#!/usr/bin/env python3
"""Sync structured CVE/CWE/KEV data from Snowflake into Neo4j."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Snowflake → Neo4j: (1) CVE/CWE/KEV, (2) ATT&CK techniques, "
            "(3) optional CVE–Technique links from advisory chunk co-occurrence."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_sync = sub.add_parser("sync", help="CVE/CWE/KEV sync (option A)")
    p_sync.add_argument(
        "--full",
        action="store_true",
        help="Scan all cve_records in batches (LIMIT/OFFSET), not only loaded_to_neo4j = FALSE",
    )
    p_sync.add_argument("--batch-size", type=int, default=200)
    p_sync.add_argument(
        "--neo4j-database",
        type=str,
        default=None,
        help="Neo4j database name; omit to use NEO4J_DATABASE from .env or server default",
    )
    p_sync.add_argument(
        "--max-batches",
        type=int,
        default=None,
        help="Stop after N batches (for testing)",
    )

    p_attack = sub.add_parser(
        "attack-techniques",
        help="Option B: MERGE attack_techniques rows as (:Technique) in Neo4j",
    )
    p_attack.add_argument("--full", action="store_true")
    p_attack.add_argument("--batch-size", type=int, default=500)
    p_attack.add_argument("--neo4j-database", type=str, default=None)
    p_attack.add_argument("--max-batches", type=int, default=None)

    p_links = sub.add_parser(
        "chunk-technique-links",
        help="Option B: CVE–Technique edges from advisory_chunks co-occurrence (run after techniques + CVEs)",
    )
    p_links.add_argument("--batch-size", type=int, default=200)
    p_links.add_argument("--neo4j-database", type=str, default=None)
    p_links.add_argument("--max-batches", type=int, default=None)

    args = parser.parse_args()
    if args.command == "sync":
        from ingestion.graph_sync import run_cve_cwe_kev_sync

        stats = run_cve_cwe_kev_sync(
            batch_size=args.batch_size,
            full=args.full,
            neo4j_database=args.neo4j_database,
            max_batches=args.max_batches,
        )
        print(
            "batches={batches} cves_processed={cves_processed} "
            "cwes_touched={cwes_touched} relationships_merged={relationships_merged} "
            "full_scan={full_scan} neo4j_database={neo4j_database}".format(**stats)
        )
        return 0

    if args.command == "attack-techniques":
        from ingestion.graph_sync import run_attack_techniques_sync

        stats = run_attack_techniques_sync(
            batch_size=args.batch_size,
            full=args.full,
            neo4j_database=args.neo4j_database,
            max_batches=args.max_batches,
        )
        print(
            "batches={batches} techniques_merged={techniques_merged} "
            "full_scan={full_scan} neo4j_database={neo4j_database}".format(**stats)
        )
        return 0

    if args.command == "chunk-technique-links":
        from ingestion.graph_sync import run_chunk_technique_link_sync

        stats = run_chunk_technique_link_sync(
            batch_size=args.batch_size,
            neo4j_database=args.neo4j_database,
            max_batches=args.max_batches,
        )
        print(
            "batches={batches} unique_pairs_merged={unique_pairs_merged} "
            "neo4j_database={neo4j_database}".format(**stats)
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
