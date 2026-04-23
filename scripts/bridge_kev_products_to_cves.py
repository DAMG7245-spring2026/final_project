#!/usr/bin/env python3
"""Bridge KEV products to CVEs via *sibling-CVE transitivity*.

When a CISA advisory discusses several CVEs against the same product, Phase
1's triplet extractor often catches only one of them — leaving the others as
orphan ``:CVE`` nodes even though the advisory clearly attributes the whole
product's exploitation to a specific threat actor.

Example (``aa23-131a``, the PaperCut print-server advisory):

  (CVE-2023-27350) -[:AFFECTS]-> (:Malware "PaperCut NG")      ← extracted
  (Bl00dy)         -[:EXPLOITS]-> (CVE-2023-27350)             ← extracted
  (CVE-2023-27351) -[:AFFECTS]-> (:Malware "PaperCut NG")      ← MISSING
  (Bl00dy)         -[:EXPLOITS]-> (CVE-2023-27351)             ← MISSING

Both CVEs are KEV, but only 27350 has a named actor in graph. This script
fills the gap: for each KEV CVE in Snowflake, find a *sibling CVE* that

  1. is linked via ``:AFFECTS`` to a product node whose name matches the
     target CVE's ``kev_vendor_project`` / ``kev_product``, AND
  2. has an ``:EXPLOITS`` edge from some source (Actor/Malware/Campaign)
     sourced from the SAME advisory as the AFFECTS edge.

The shared ``advisory_id`` is the anchor that keeps this tight: it means
"one advisory named this product, named this actor, and listed both CVEs" —
at that point inferring (actor)-[:EXPLOITS]->(missing CVE) is very safe.

Source types supported: ``:Actor``, ``:Malware``, ``:Campaign`` (all three
have real EXPLOITS edges in the graph today).

Idempotent: every new edge is stamped

  r.inferred       = true
  r.bridge_source  = 'sibling_cve_kev_product'
  r.sibling_cve    = '<the CVE the evidence actually came from>'
  r.matched_product= '<the product-like node that linked them>'
  r.advisory_id    = '<source advisory>'
  r.created_at     = datetime()

Rollback: one Cypher —

  MATCH ()-[r:EXPLOITS {bridge_source:'sibling_cve_kev_product'}]->()
  DELETE r

Usage:
  .venv/bin/python scripts/bridge_kev_products_to_cves.py                      # dry-run (all KEV)
  .venv/bin/python scripts/bridge_kev_products_to_cves.py --cve CVE-2023-27351 # dry-run one
  .venv/bin/python scripts/bridge_kev_products_to_cves.py --commit             # write
  .venv/bin/python scripts/bridge_kev_products_to_cves.py --commit --cve CVE-2023-27351
"""
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
log = logging.getLogger("bridge_kev")


_KEV_SQL_ALL = """
SELECT cve_id, kev_vendor_project, kev_product
FROM cve_records
WHERE is_kev = TRUE
  AND vuln_status <> 'REJECTED'
  AND kev_product IS NOT NULL
  AND kev_vendor_project IS NOT NULL
"""

_KEV_SQL_ONE = _KEV_SQL_ALL + "  AND cve_id = %(cve_id)s\n"


# Dry-run: sibling-CVE traversal, no writes. Shows exactly what edges we
# WOULD create (source node, the sibling CVE we borrowed the attribution
# from, the matched product node, and the source advisory).
_PREVIEW_CYPHER = """
MATCH (c_missing:CVE {id: $cve_id})
MATCH (src)-[exploits:EXPLOITS]->(c_sibling:CVE)-[affects:AFFECTS]->(m)
WHERE (src:Actor OR src:Malware OR src:Campaign)
  AND (m:Malware OR m:Other)
  AND (toLower(m.name) CONTAINS toLower($product)
       OR toLower(m.name) CONTAINS toLower($vendor))
  AND exploits.advisory_id IS NOT NULL
  AND exploits.advisory_id = affects.advisory_id
  AND c_sibling.id <> $cve_id
RETURN labels(src)[0]    AS src_label,
       src.name          AS src_name,
       c_sibling.id      AS sibling_cve,
       m.name            AS matched_product,
       exploits.advisory_id AS advisory
"""

# Commit: same traversal + MERGE. exists() in the WITH clause captures the
# pre-MERGE state so we can distinguish new vs. existing accurately on re-runs.
_MERGE_CYPHER = """
MATCH (c_missing:CVE {id: $cve_id})
MATCH (src)-[exploits:EXPLOITS]->(c_sibling:CVE)-[affects:AFFECTS]->(m)
WHERE (src:Actor OR src:Malware OR src:Campaign)
  AND (m:Malware OR m:Other)
  AND (toLower(m.name) CONTAINS toLower($product)
       OR toLower(m.name) CONTAINS toLower($vendor))
  AND exploits.advisory_id IS NOT NULL
  AND exploits.advisory_id = affects.advisory_id
  AND c_sibling.id <> $cve_id
WITH c_missing, src, m, c_sibling, exploits,
     exists((src)-[:EXPLOITS]->(c_missing)) AS existed
MERGE (src)-[r:EXPLOITS]->(c_missing)
  ON CREATE SET r.inferred = true,
                r.bridge_source = 'sibling_cve_kev_product',
                r.sibling_cve = c_sibling.id,
                r.matched_product = m.name,
                r.advisory_id = exploits.advisory_id,
                r.created_at = datetime()
RETURN labels(src)[0]    AS src_label,
       src.name          AS src_name,
       c_sibling.id      AS sibling_cve,
       m.name            AS matched_product,
       exploits.advisory_id AS advisory,
       CASE WHEN existed THEN 'existing' ELSE 'new' END AS edge_status
"""


def _fmt_candidates(rows: list[dict], n: int = 5) -> list[tuple]:
    """Compact representation for log lines — keeps the line short."""
    return [
        (r["src_label"], r["src_name"], r["sibling_cve"], r["advisory"])
        for r in rows[:n]
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Actually write to Neo4j. Default: dry-run (no writes).",
    )
    parser.add_argument(
        "--cve",
        help="Limit to a single CVE ID (e.g. CVE-2023-27351).",
    )
    args = parser.parse_args()

    from app.services import get_neo4j_service, get_snowflake_service

    sf = get_snowflake_service()
    neo = get_neo4j_service()

    if args.cve:
        rows = sf.execute_query(_KEV_SQL_ONE, {"cve_id": args.cve})
    else:
        rows = sf.execute_query(_KEV_SQL_ALL)

    mode = "COMMIT" if args.commit else "DRY-RUN"
    log.info("kev_rows=%d mode=%s", len(rows), mode)

    total_new = 0
    total_existing = 0
    total_unmatched = 0
    total_matched_cves = 0

    for r in rows:
        cve_id = r["cve_id"]
        vendor = r["kev_vendor_project"]
        product = r["kev_product"]
        params = {"cve_id": cve_id, "vendor": vendor, "product": product}

        if not args.commit:
            preview = neo.execute_query(_PREVIEW_CYPHER, params)
            if preview:
                total_matched_cves += 1
                log.info(
                    "DRY-RUN %s vendor=%r product=%r -> %d candidate(s): %s",
                    cve_id,
                    vendor,
                    product,
                    len(preview),
                    _fmt_candidates(preview),
                )
            else:
                total_unmatched += 1
                log.info(
                    "DRY-RUN %s vendor=%r product=%r -> no sibling-CVE evidence",
                    cve_id,
                    vendor,
                    product,
                )
            continue

        created = neo.execute_query(_MERGE_CYPHER, params)
        new_here = sum(1 for x in created if x.get("edge_status") == "new")
        existing_here = sum(1 for x in created if x.get("edge_status") == "existing")
        total_new += new_here
        total_existing += existing_here
        if not created:
            total_unmatched += 1
            log.info(
                "COMMIT %s vendor=%r product=%r -> no sibling-CVE evidence (skipped)",
                cve_id,
                vendor,
                product,
            )
        else:
            total_matched_cves += 1
            log.info(
                "COMMIT %s -> edges=%d new=%d existing=%d sample=%s",
                cve_id,
                len(created),
                new_here,
                existing_here,
                _fmt_candidates(created, n=3),
            )

    log.info(
        "DONE mode=%s kev_total=%d matched_cves=%d unmatched_cves=%d "
        "edges_new=%d edges_existing=%d",
        mode,
        len(rows),
        total_matched_cves,
        total_unmatched,
        total_new,
        total_existing,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
