# Integration tests

These tests treat the **live** Snowflake / Neo4j / S3 state as the source of
truth. They pick one fully-processed advisory from prod, fetch its HTML
from S3, and verify that running the pipeline code reproduces what is
already persisted. No mock schemas, no stubbed LLM, no seed data.

## Running

```bash
poetry run pytest -m integration -v                                # whole suite
poetry run pytest tests/integration/test_hybrid_search_e2e.py -v   # single file
poetry run pytest -m "not integration"                             # CI default (skip these)
```

Env vars required (all must be present or the suite skips): `SNOWFLAKE_*`,
`NEO4J_*`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `S3_BUCKET`.

## How it works

Every test requests the session-scoped `ground_truth_advisory` fixture,
which runs this query and locks onto the top result:

```sql
-- In plain english: pick the advisory that has everything — HTML in S3,
-- embedded chunks in Snowflake, triplets extracted, Neo4j loaded — and
-- has the most triplets (richest ground truth). Deterministic via ORDER BY.
```

From that one advisory we derive every assertion:

| Test file | What it verifies |
| --------- | ---------------- |
| `test_advisory_pipeline_e2e.py` | `chunk_advisory()` on the S3 HTML reproduces the `content_hash`, section names, and CVE/CWE/MITRE arrays already in `advisory_chunks`. Every persisted embedding is 1024-dim. |
| `test_triplet_flow_e2e.py` | Every relation type in `extracted_triplets` has at least one edge in Neo4j. Neo4j edge count ≤ triplet count per relation (MERGE dedupes). One sampled `exploits` triplet resolves to a real edge. No alias leakage in the triplet table. |
| `test_hybrid_search_e2e.py` | Querying hybrid_search with the advisory's own title puts that advisory in the top-20. `document_types` filter is respected. `cve_ids` filter only returns chunks that actually contain the CVE. Every result carries RRF annotations. |

## Safety

All queries are read-only:

- Snowflake: `SELECT` only — never `INSERT`/`UPDATE`/`DELETE` on prod tables.
- Neo4j: `MATCH` only — never writes.
- S3: `GetObject` only — never `PutObject`.

You can run this suite against prod without fear of corrupting data.

## Why this is more powerful than mocked integration tests

Every assertion is against **actual** production state. If anyone changes
the chunker, the triplet loader, or the hybrid search fusion without
understanding the downstream effect, these tests fail immediately on the
specific advisory in prod — not on a toy fixture that was carefully set
up to pass. Regressions show up as real drift from reality.

## Adding a new integration test

1. Request `ground_truth_advisory` and (if you need search) `bm25_loaded`.
2. Pull whatever you want to verify from Snowflake / Neo4j.
3. Run the pipeline function under test and compare to step 2.
4. Mark the module with `pytestmark = pytest.mark.integration`.
