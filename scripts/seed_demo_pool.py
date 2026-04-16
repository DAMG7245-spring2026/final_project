"""
Step 0-2: Select ~100 representative advisories and populate demonstration_pool
with concatenated full report text.

Usage:
  poetry run python scripts/seed_demo_pool.py              # dry-run (preview only)
  poetry run python scripts/seed_demo_pool.py --commit      # actually write to Snowflake
"""
import argparse
import json
import random

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector
from app.config import get_settings

# How many demos to pick per document_type.
# Small types get proportionally more to ensure coverage.
QUOTA = {
    "MAR": 35,
    "JOINT_CSA": 35,
    "CSA": 12,
    "STOPRANSOMWARE": 10,
    "ANALYSIS_REPORT": 5,
    "IR_LESSONS": 3,
}

# Skip extremely short (<500 tokens) or extremely long (>20000 tokens) reports.
# Short ones have too little content; long ones blow up prompt context.
MIN_TOKENS = 500
MAX_TOKENS = 20000

SEED = 42


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Actually write to Snowflake")
    parser.add_argument("--seed", type=int, default=SEED, help="Random seed")
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

    # Get all advisories with their total token counts
    cur.execute("""
        SELECT a.advisory_id, a.document_type, a.title,
               SUM(c.token_count) as total_tokens
        FROM advisories a
        JOIN advisory_chunks c ON a.advisory_id = c.advisory_id
        WHERE a.document_type IS NOT NULL
        GROUP BY a.advisory_id, a.document_type, a.title
        ORDER BY a.document_type, a.advisory_id
    """)
    all_rows = cur.fetchall()

    # Group by document_type and filter by token range
    by_type: dict[str, list] = {}
    skipped_short = 0
    skipped_long = 0
    for row in all_rows:
        advisory_id, doc_type, title, total_tokens = row
        if total_tokens < MIN_TOKENS:
            skipped_short += 1
            continue
        if total_tokens > MAX_TOKENS:
            skipped_long += 1
            continue
        by_type.setdefault(doc_type, []).append(row)

    print(f"Eligible advisories (tokens {MIN_TOKENS}-{MAX_TOKENS}):")
    print(f"  Skipped too short (<{MIN_TOKENS}): {skipped_short}")
    print(f"  Skipped too long (>{MAX_TOKENS}): {skipped_long}")
    for dt, rows in sorted(by_type.items()):
        print(f"  {dt:<20} {len(rows):>3} eligible")
    print()

    # Random sample per type
    rng = random.Random(args.seed)
    selected: list[tuple] = []
    for doc_type, quota in QUOTA.items():
        pool = by_type.get(doc_type, [])
        n = min(quota, len(pool))
        picked = rng.sample(pool, n)
        selected.extend(picked)
        print(f"  {doc_type:<20} picked {n}/{quota} (from {len(pool)} eligible)")

    print(f"\nTotal selected: {len(selected)}")

    # Check what's already in demonstration_pool
    cur.execute("SELECT advisory_id FROM demonstration_pool")
    existing = {r[0] for r in cur.fetchall()}
    new_selected = [r for r in selected if r[0] not in existing]
    print(f"Already in demo pool: {len(selected) - len(new_selected)}")
    print(f"New to insert: {len(new_selected)}")

    if not new_selected:
        print("\nNothing new to insert.")
        conn.close()
        return

    if not args.commit:
        print("\n[DRY-RUN] Would insert these advisories:")
        for i, (aid, dt, title, tokens) in enumerate(new_selected, 1):
            print(f"  {i:3d}. {aid:<14} {dt:<16} {tokens:>6} tok  {(title or '')[:55]}")
        print(f"\nRerun with --commit to write to Snowflake.")
        conn.close()
        return

    # For each selected advisory, concat chunks into full report text
    print("\nInserting into demonstration_pool...")
    demo_num = len(existing)  # continue numbering from existing

    for i, (advisory_id, doc_type, title, total_tokens) in enumerate(new_selected, 1):
        demo_num += 1
        demo_id = f"demo_{demo_num:03d}"

        # Fetch chunks ordered by chunk_index, concat
        cur.execute("""
            SELECT chunk_text
            FROM advisory_chunks
            WHERE advisory_id = %s
            ORDER BY chunk_index
        """, (advisory_id,))
        chunks = cur.fetchall()
        report_text = "\n\n".join(row[0] for row in chunks)

        # Insert with NULL gold_triplets and NULL demo_embedding (filled later)
        cur.execute("""
            INSERT INTO demonstration_pool (demo_id, advisory_id, document_type, report_text, gold_triplets, demo_embedding)
            SELECT %s, %s, %s, %s, NULL, NULL
        """, (demo_id, advisory_id, doc_type, report_text))

        print(f"  [{i:3d}/{len(new_selected)}] {demo_id} ← {advisory_id:<14} {doc_type:<16} {total_tokens:>6} tok")

    conn.commit()
    print(f"\nDone. Inserted {len(new_selected)} rows into demonstration_pool.")
    print("Next steps:")
    print("  1. Generate gold_triplets (Step 0-3)")
    print("  2. Compute demo_embedding (Step 0-5)")
    conn.close()


if __name__ == "__main__":
    main()
