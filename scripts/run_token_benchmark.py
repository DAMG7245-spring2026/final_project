"""
Token benchmark: runs all three LLM pipeline stages for N advisories and
logs token usage to llm_token_log. No pipeline data is written.

  triplet_extraction   — GPT-4o, no write to extracted_triplets
  entity_deduplication — GPT-4o, no write to entity_aliases
  relation_inference   — GPT-4o / GPT-4o-mini, no write to Neo4j

Usage:
  poetry run python scripts/run_token_benchmark.py            # 50 advisories
  poetry run python scripts/run_token_benchmark.py --limit 10
"""
import argparse
import json
import re
import time

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector
from neo4j import GraphDatabase
from openai import OpenAI

from app.config import get_settings
from app.token_logger import log_llm_call
from scripts.extract_triplets import TOP_K_DEMOS, build_prompt
from scripts.infer_relations import (
    build_components,
    find_central_entity,
    get_advisory_graph,
    get_node_degrees,
    get_node_subject_counts,
    get_report_text,
    infer_relation,
    out_degrees_count,
    validate_inference,
)

EMBED_MODEL = "snowflake-arctic-embed-l-v2.0"
SIM_THRESHOLD = 0.85
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{16,}$")

DEDUP_SYSTEM = (
    "You are a cybersecurity knowledge graph expert.\n"
    "Given two entity names from threat intelligence reports, determine:\n"
    "1. Are they the same real-world entity? (yes/no)\n"
    "2. If yes, which name is the canonical (most widely used) name?\n\n"
    'Respond with a single JSON object:\n{"same_entity": true/false, "canonical_name": "<name or null>"}\n'
    "No explanation."
)


def _is_named_entity(name: str) -> bool:
    return not IP_RE.match(name) and not HASH_RE.match(name) and len(name) >= 3


def ensure_token_log_table(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS llm_token_log (
            log_id            VARCHAR(36)   NOT NULL DEFAULT UUID_STRING(),
            called_at         TIMESTAMP_TZ  NOT NULL DEFAULT CURRENT_TIMESTAMP(),
            pipeline_stage    VARCHAR(64)   NOT NULL,
            model             VARCHAR(64)   NOT NULL,
            request_id        VARCHAR(32),
            prompt_tokens     INTEGER       NOT NULL,
            completion_tokens INTEGER       NOT NULL,
            total_tokens      INTEGER       NOT NULL,
            cost_usd          FLOAT         NOT NULL,
            advisory_id       VARCHAR(64),
            latency_ms        INTEGER,
            PRIMARY KEY (log_id)
        )
    """)


# ── Stage 1 ───────────────────────────────────────────────────────────────────

def run_extraction(cur, client, model: str, limit: int, conn) -> int:
    print(f"\n{'='*65}")
    print(f"  Stage 1 · Triplet Extraction  ({limit} advisories, model={model})")
    print(f"{'='*65}")

    cur.execute("""
        SELECT advisory_id
        FROM advisories
        WHERE report_embedding IS NOT NULL
        ORDER BY advisory_id
        LIMIT %s
    """, (limit,))
    advisory_ids = [r[0] for r in cur.fetchall()]
    print(f"  Advisories selected: {len(advisory_ids)}")

    calls = prompt_total = completion_total = 0

    for i, advisory_id in enumerate(advisory_ids, 1):
        cur.execute("""
            SELECT d.demo_id, d.advisory_id, d.gold_triplets, d.report_text,
                   VECTOR_COSINE_SIMILARITY(d.demo_embedding, a.report_embedding) AS score
            FROM demonstration_pool d, advisories a
            WHERE a.advisory_id = %s
              AND d.advisory_id != %s
              AND d.demo_embedding IS NOT NULL
              AND a.report_embedding IS NOT NULL
            ORDER BY score DESC
            LIMIT %s
        """, (advisory_id, advisory_id, TOP_K_DEMOS))
        demos = cur.fetchall()

        cur.execute("""
            SELECT LISTAGG(chunk_text, '\n\n') WITHIN GROUP (ORDER BY chunk_index)
            FROM advisory_chunks
            WHERE advisory_id = %s
        """, (advisory_id,))
        row = cur.fetchone()
        report_text = row[0] if row and row[0] else ""

        if not report_text or not demos:
            print(f"  [{i:>3}/{len(advisory_ids)}] {advisory_id} — skipped (no text or demos)")
            continue

        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": build_prompt(demos, report_text)}],
                temperature=0,
                max_tokens=4000,
            )

            log_llm_call(
                pipeline_stage="triplet_extraction",
                model=model,
                prompt_tokens=resp.usage.prompt_tokens,
                completion_tokens=resp.usage.completion_tokens,
                advisory_id=advisory_id,
                cur=cur,
            )
            prompt_total += resp.usage.prompt_tokens
            completion_total += resp.usage.completion_tokens
            calls += 1
            print(f"  [{i:>3}/{len(advisory_ids)}] {advisory_id}  "
                  f"{resp.usage.prompt_tokens}p + {resp.usage.completion_tokens}c")
        except Exception as e:
            print(f"  [{i:>3}/{len(advisory_ids)}] {advisory_id} — error: {e}")

    conn.commit()
    print(f"\n  → {calls} calls  |  {prompt_total:,} prompt  {completion_total:,} completion tokens")
    return calls


# ── Stage 2 ───────────────────────────────────────────────────────────────────

def run_deduplication(cur, client, model: str, conn) -> int:
    print(f"\n{'='*65}")
    print(f"  Stage 2 · Entity Deduplication  (model={model})")
    print(f"{'='*65}")

    cur.execute("""
        SELECT DISTINCT subject AS entity FROM extracted_triplets
        UNION
        SELECT DISTINCT object  AS entity FROM extracted_triplets
    """)
    named = [r[0].strip() for r in cur.fetchall() if r[0] and _is_named_entity(r[0].strip())]
    print(f"  Named entities: {len(named)}")

    if len(named) < 2:
        print("  Not enough entities — skipping stage.")
        return 0

    cur.execute(
        "CREATE OR REPLACE TEMPORARY TABLE _bench_embed "
        "(entity_name VARCHAR(500), embedding VECTOR(FLOAT, 1024))"
    )
    placeholders = ", ".join("(%s)" for _ in named)
    cur.execute(f"INSERT INTO _bench_embed (entity_name) VALUES {placeholders}", named)
    cur.execute(
        "UPDATE _bench_embed SET embedding = "
        "SNOWFLAKE.CORTEX.EMBED_TEXT_1024(%s, entity_name)",
        (EMBED_MODEL,),
    )

    cur.execute("""
        SELECT a.entity_name, b.entity_name
        FROM _bench_embed a, _bench_embed b
        WHERE a.entity_name < b.entity_name
          AND VECTOR_COSINE_SIMILARITY(a.embedding, b.embedding) >= %s
        ORDER BY VECTOR_COSINE_SIMILARITY(a.embedding, b.embedding) DESC
    """, (SIM_THRESHOLD,))
    pairs = cur.fetchall()
    print(f"  Candidate pairs (sim >= {SIM_THRESHOLD}): {len(pairs)}")

    calls = prompt_total = completion_total = 0

    for name_a, name_b in pairs:
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": DEDUP_SYSTEM},
                    {"role": "user", "content": f'Entity A: "{name_a}"\nEntity B: "{name_b}"'},
                ],
                temperature=0,
                max_tokens=60,
                response_format={"type": "json_object"},
            )

            log_llm_call(
                pipeline_stage="entity_deduplication",
                model=model,
                prompt_tokens=resp.usage.prompt_tokens,
                completion_tokens=resp.usage.completion_tokens,
                cur=cur,
            )
            prompt_total += resp.usage.prompt_tokens
            completion_total += resp.usage.completion_tokens
            calls += 1
        except Exception as e:
            print(f"  !! ({name_a}, {name_b}): {e}")

    conn.commit()
    print(f"\n  → {calls} calls  |  {prompt_total:,} prompt  {completion_total:,} completion tokens")
    return calls


# ── Stage 3 ───────────────────────────────────────────────────────────────────

def run_inference(cur, client, driver, model: str, limit: int, conn) -> int:
    print(f"\n{'='*65}")
    print(f"  Stage 3 · Relation Inference  (model={model}, up to {limit} advisories)")
    print(f"{'='*65}")

    with driver.session() as session:
        result = session.run(
            "MATCH ()-[r]->() WHERE r.advisory_id IS NOT NULL "
            "RETURN DISTINCT r.advisory_id AS aid ORDER BY aid"
        )
        advisory_ids = [rec["aid"] for rec in result][:limit]

    print(f"  Advisories in graph with edges: {len(advisory_ids)}")

    calls = prompt_total = completion_total = processed = 0

    with driver.session() as session:
        for advisory_id in advisory_ids:
            edges_data = get_advisory_graph(session, advisory_id)
            if not edges_data:
                continue

            node_ids = list(
                {row["s_eid"] for row in edges_data} | {row["o_eid"] for row in edges_data}
            )
            edges = [(row["s_eid"], row["o_eid"]) for row in edges_data]
            components = build_components(node_ids, edges)

            if len(components) <= 1:
                continue

            processed += 1
            node_info = {}
            for row in edges_data:
                node_info[row["s_eid"]] = {"name": row["s_name"], "labels": row["s_labels"]}
                node_info[row["o_eid"]] = {"name": row["o_name"], "labels": row["o_labels"]}

            degrees = get_node_degrees(edges_data)
            out_degrees = {
                row["s_eid"]: out_degrees_count(row["s_eid"], edges_data)
                for row in edges_data
            }
            subject_counts = get_node_subject_counts(edges_data)

            centrals = [
                find_central_entity(members, degrees, out_degrees, subject_counts)
                for members in components.values()
            ]
            topic_eid = max(
                centrals,
                key=lambda n: (degrees.get(n, 0), out_degrees.get(n, 0), subject_counts.get(n, 0)),
            )
            topic_name = node_info[topic_eid]["name"]
            report_text = get_report_text(cur, advisory_id)

            for c_eid in centrals:
                if c_eid == topic_eid:
                    continue
                candidate_name = node_info[c_eid]["name"]

                result, infer_usage = infer_relation(
                    client, candidate_name, topic_name, report_text, model
                )
                if infer_usage is not None:
                    log_llm_call(
                        pipeline_stage="relation_inference",
                        model=model,
                        prompt_tokens=infer_usage.prompt_tokens,
                        completion_tokens=infer_usage.completion_tokens,
                        advisory_id=advisory_id,
                        cur=cur,
                    )

                    prompt_total += infer_usage.prompt_tokens
                    completion_total += infer_usage.completion_tokens
                    calls += 1

                if result is not None:
                    valid, val_usage = validate_inference(
                        client, result["subject"], result["relation"], result["object"],
                        model="gpt-4o-mini",
                    )
                    if val_usage is not None:
                        log_llm_call(
                            pipeline_stage="relation_inference",
                            model="gpt-4o-mini",
                            prompt_tokens=val_usage.prompt_tokens,
                            completion_tokens=val_usage.completion_tokens,
                            advisory_id=advisory_id,
                            cur=cur,
                        )
                        prompt_total += val_usage.prompt_tokens
                        completion_total += val_usage.completion_tokens
                        calls += 1

    conn.commit()
    print(f"  Advisories with disconnected subgraphs: {processed}")
    print(f"\n  → {calls} calls  |  {prompt_total:,} prompt  {completion_total:,} completion tokens")
    return calls


# ── Cost breakdown ─────────────────────────────────────────────────────────────

def print_cost_breakdown(cur):
    cur.execute("""
        SELECT
            pipeline_stage,
            COUNT(*)                        AS call_count,
            SUM(prompt_tokens)              AS prompt_tokens,
            SUM(completion_tokens)          AS completion_tokens,
            SUM(total_tokens)               AS total_tokens
        FROM llm_token_log
        GROUP BY pipeline_stage
        ORDER BY total_tokens DESC
    """)
    rows = cur.fetchall()

    print(f"\n{'='*75}")
    print(f"  LLM Token Cost Breakdown by Pipeline Stage")
    print(f"{'='*75}")
    print(f"  {'Stage':<25} {'Calls':>6}  {'Prompt':>9}  {'Completion':>10}  {'Total':>9}")
    print(f"  {'─'*25} {'─'*6}  {'─'*9}  {'─'*10}  {'─'*9}")

    total_tokens = 0
    for stage, calls, prompt, completion, total in rows:
        total = total or 0
        total_tokens += total
        print(f"  {stage:<25} {calls:>6}  {prompt:>9,}  {completion:>10,}  {total:>9,}")

    print(f"  {'─'*65}")
    print(f"  {'TOTAL':<25} {'':>6}  {'':>9}  {'':>10}  {total_tokens:>9,}")
    print(f"{'='*65}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=50, help="Advisories per stage (default 50)")
    parser.add_argument("--model", default="gpt-4o")
    parser.add_argument("--skip-dedup", action="store_true", help="Skip Stage 2 entity deduplication")
    args = parser.parse_args()

    s = get_settings()
    conn = snowflake.connector.connect(
        account=s.snowflake_account,
        user=s.snowflake_user,
        password=s.snowflake_password,
        database=s.snowflake_database,
        schema=s.snowflake_schema,
        warehouse=s.snowflake_warehouse,
    )
    cur = conn.cursor()
    client = OpenAI(api_key=s.openai_api_key)
    driver = GraphDatabase.driver(
        s.neo4j_uri, auth=(s.neo4j_username, s.neo4j_password)
    )

    ensure_token_log_table(cur)
    conn.commit()

    t_start = time.perf_counter()

    run_extraction(cur, client, args.model, args.limit, conn)
    if not args.skip_dedup:
        run_deduplication(cur, client, args.model, conn)
    run_inference(cur, client, driver, args.model, args.limit, conn)

    elapsed = time.perf_counter() - t_start
    print(f"\nTotal wall-clock time: {elapsed:.1f}s")

    print_cost_breakdown(cur)

    cur.close()
    conn.close()
    driver.close()


if __name__ == "__main__":
    main()
