"""
Phase 2 Steps 2-2 to 2-6: Full entity alignment pipeline.

Steps:
  2-2: Collect unique entity names + classify entity type
  2-3: Compute embeddings (Snowflake Cortex)
  2-4: Find candidate alias pairs via cosine similarity >= 0.85
  2-5: GPT-4o binary classification → write to entity_aliases
  2-6: Update extracted_triplets subject/object + dedup

Usage:
  poetry run python scripts/align_entities.py              # dry-run
  poetry run python scripts/align_entities.py --limit 10  # dry-run, 10 named entities
  poetry run python scripts/align_entities.py --commit     # full pipeline, write to DB
"""
import argparse
import json
import re

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector
from openai import OpenAI

from app.config import get_settings
from scripts.collect_entities import pattern_classify, llm_classify

# ── Constants ────────────────────────────────────────────────────────────────

EMBED_MODEL   = "snowflake-arctic-embed-l-v2.0"
SIM_THRESHOLD = 0.85

IP_RE   = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
HASH_RE = re.compile(r'^[0-9a-fA-F]{16,}$')

SYSTEM_PROMPT = """You are a cybersecurity knowledge graph expert.
Given two entity names from threat intelligence reports, determine:
1. Are they the same real-world entity? (yes/no)
2. If yes, which name is the canonical (most widely used) name?

Respond with a single JSON object:
{"same_entity": true/false, "canonical_name": "<name or null>"}
No explanation."""


# ── Helpers ───────────────────────────────────────────────────────────────────

def is_named_entity(name: str) -> bool:
    if IP_RE.match(name):
        return False
    if HASH_RE.match(name):
        return False
    if len(name) < 3:
        return False
    return True


def gpt4o_classify_pair(name_a: str, name_b: str, client: OpenAI, model: str) -> tuple[bool, str | None]:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f'Entity A: "{name_a}"\nEntity B: "{name_b}"'},
            ],
            temperature=0,
            max_tokens=60,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content.strip()
        parsed = json.loads(raw)
        same = parsed.get("same_entity", False)
        canonical = parsed.get("canonical_name")
        return same, canonical
    except Exception as e:
        print(f"  !! GPT-4o failed for ({name_a}, {name_b}): {e}")
        return False, None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Write to DB (default: dry-run)")
    parser.add_argument("--limit", type=int, default=0, help="Limit named entities (0 = all)")
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model for pair classification")
    parser.add_argument("--type-model", default="gpt-4o-mini", help="OpenAI model for entity type")
    parser.add_argument("--sim-threshold", type=float, default=SIM_THRESHOLD)
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

    mode = "COMMIT" if args.commit else "DRY-RUN"
    print(f"[{mode}] sim_threshold={args.sim_threshold}")

    # ── Step 2-2: Collect unique named entities + classify type ───────────────
    print("\nStep 2-2: Collecting entities...")
    cur.execute("""
        SELECT DISTINCT subject AS entity FROM extracted_triplets
        UNION
        SELECT DISTINCT object  AS entity FROM extracted_triplets
    """)
    all_entities = sorted({r[0].strip() for r in cur.fetchall() if r[0] and r[0].strip()})
    named = [e for e in all_entities if is_named_entity(e)]
    if args.limit:
        alpha = [e for e in named if e[0].isalpha()]
        named = alpha[:args.limit] if len(alpha) >= args.limit else named[:args.limit]

    print(f"  Total unique entities : {len(all_entities)}")
    print(f"  Named entities        : {len(named)}")

    if len(named) < 2:
        print("Not enough named entities to find pairs.")
        conn.close()
        return

    print("\n  Classifying entity types...")
    entities: list[tuple[str, str]] = []
    for i, name in enumerate(named, 1):
        entity_type = pattern_classify(name) or llm_classify(name, client, args.type_model)
        entities.append((name, entity_type))
        if i % 50 == 0 or i == len(named):
            print(f"  [{i}/{len(named)}] classified")

    type_counts: dict[str, int] = {}
    for _, t in entities:
        type_counts[t] = type_counts.get(t, 0) + 1
    print("  " + "  ".join(f"{t}={c}" for t, c in sorted(type_counts.items())))

    # ── Step 2-3: Embedding via Snowflake Cortex ──────────────────────────────
    print(f"\nStep 2-3: Computing embeddings ({EMBED_MODEL})...")
    cur.execute("CREATE OR REPLACE TEMPORARY TABLE entity_embed_temp (entity_name VARCHAR(500), entity_type VARCHAR(50), embedding VECTOR(FLOAT, 1024))")
    placeholders = ", ".join("(%s, %s)" for _ in entities)
    values = [v for name, etype in entities for v in (name, etype)]
    cur.execute(f"INSERT INTO entity_embed_temp (entity_name, entity_type) VALUES {placeholders}", values)
    cur.execute("UPDATE entity_embed_temp SET embedding = SNOWFLAKE.CORTEX.EMBED_TEXT_1024(%s, entity_name)", (EMBED_MODEL,))
    conn.commit()
    print(f"  Embedded {len(entities)} entities")

    # ── Step 2-4: Cosine similarity → candidate pairs ─────────────────────────
    print(f"\nStep 2-4: Finding candidate pairs (threshold={args.sim_threshold})...")
    cur.execute("""
        SELECT a.entity_name, a.entity_type, b.entity_name, b.entity_type,
               VECTOR_COSINE_SIMILARITY(a.embedding, b.embedding) AS score
        FROM entity_embed_temp a, entity_embed_temp b
        WHERE a.entity_name < b.entity_name
          AND VECTOR_COSINE_SIMILARITY(a.embedding, b.embedding) >= %s
        ORDER BY score DESC
    """, (args.sim_threshold,))
    candidate_pairs = cur.fetchall()
    print(f"  Candidate pairs: {len(candidate_pairs)}")

    if not candidate_pairs:
        print("No candidate pairs found. Try lowering --sim-threshold.")
        conn.close()
        return

    # ── Step 2-5: GPT-4o binary classification ────────────────────────────────
    print(f"\nStep 2-5: GPT-4o classification ({len(candidate_pairs)} pairs)...")
    approved: dict[str, tuple[str, str]] = {}

    for i, (name_a, type_a, name_b, type_b, score) in enumerate(candidate_pairs, 1):
        print(f"  [{i}/{len(candidate_pairs)}] '{name_a}' ↔ '{name_b}'  (sim={score:.3f})")

        same, canonical = gpt4o_classify_pair(name_a, name_b, client, args.model)
        print(f"    same={same}  canonical={canonical}")

        if not same or not canonical:
            print(f"    → skipped")
            continue

        alias = name_b if canonical == name_a else name_a
        entity_type = type_a if canonical == name_a else type_b

        if alias not in approved:
            approved[alias] = (canonical, entity_type)
            print(f"    → approved: '{alias}' → '{canonical}'")

    print(f"\n  Approved mappings: {len(approved)}")

    if not args.commit:
        print(f"\n[DRY-RUN] Would write {len(approved)} rows to entity_aliases and update extracted_triplets.")
        print("Rerun with --commit to write.")
        conn.close()
        return

    # ── Write to entity_aliases ───────────────────────────────────────────────
    print(f"\nWriting {len(approved)} mappings to entity_aliases...")
    for alias, (canonical, entity_type) in approved.items():
        cur.execute("""
            MERGE INTO entity_aliases AS t
            USING (SELECT %s AS alias_name, %s AS canonical_name, %s AS entity_type) AS s
            ON t.alias_name = s.alias_name
            WHEN MATCHED THEN UPDATE SET canonical_name = s.canonical_name, entity_type = s.entity_type
            WHEN NOT MATCHED THEN INSERT (alias_name, canonical_name, entity_type) VALUES (s.alias_name, s.canonical_name, s.entity_type)
        """, (alias, canonical, entity_type))
    conn.commit()

    # ── Step 2-6: Update extracted_triplets + dedup ───────────────────────────
    print(f"\nStep 2-6: Updating extracted_triplets...")
    cur.execute("""
        UPDATE extracted_triplets t
        SET subject = ea.canonical_name
        FROM entity_aliases ea
        WHERE LOWER(t.subject) = LOWER(ea.alias_name)
    """)
    subject_updated = cur.rowcount

    cur.execute("""
        UPDATE extracted_triplets t
        SET object = ea.canonical_name
        FROM entity_aliases ea
        WHERE LOWER(t.object) = LOWER(ea.alias_name)
    """)
    object_updated = cur.rowcount
    conn.commit()
    print(f"  subject updated: {subject_updated}  object updated: {object_updated}")

    cur.execute("""
        DELETE FROM extracted_triplets
        WHERE triplet_id NOT IN (
            SELECT MIN(triplet_id)
            FROM extracted_triplets
            GROUP BY advisory_id, subject, relation, object
        )
    """)
    deleted = cur.rowcount
    conn.commit()
    print(f"  Duplicates deleted: {deleted}")

    cur.execute("SELECT COUNT(*) FROM extracted_triplets")
    total = cur.fetchone()[0]
    print(f"  extracted_triplets total: {total}")

    conn.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
