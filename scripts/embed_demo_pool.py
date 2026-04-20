"""
Step 0-5: Compute demo_embedding for demonstration_pool using Snowflake Cortex.

Model: snowflake-arctic-embed-l-v2.0  (1024-dim, 8192 token context)
Runs entirely server-side — report_text never leaves Snowflake.
Reports longer than 8192 tokens are automatically truncated by Cortex.

Usage:
  poetry run python scripts/embed_demo_pool.py              # dry-run
  poetry run python scripts/embed_demo_pool.py --write      # actually embed
"""
import argparse
import time

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector
from app.config import get_settings

EMBED_MODEL = "snowflake-arctic-embed-l-v2.0"
BATCH_SIZE = 20


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Commit UPDATEs (default: dry-run)")
    parser.add_argument("--force", action="store_true", help="Re-embed rows that already have an embedding")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
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

    where = "report_text IS NOT NULL"
    if not args.force:
        where += " AND demo_embedding IS NULL"

    cur.execute(f"SELECT COUNT(*) FROM demonstration_pool WHERE {where}")
    total = cur.fetchone()[0]
    print(f"Target : {total} demos")
    print(f"Model  : {EMBED_MODEL}  (1024-dim)")
    print(f"Batch  : {args.batch_size}")

    if total == 0:
        print("Nothing to embed.")
        conn.close()
        return

    cur.execute(f"SELECT demo_id FROM demonstration_pool WHERE {where} ORDER BY demo_id")
    demo_ids = [row[0] for row in cur.fetchall()]

    if not args.write:
        print(f"\n[dry-run] Would embed {len(demo_ids)} demos in batches of {args.batch_size}.")
        print("Rerun with --write to commit.")
        conn.close()
        return

    print(f"\nEmbedding {len(demo_ids)} demos...")
    start = time.time()
    done = 0

    for i in range(0, len(demo_ids), args.batch_size):
        batch = demo_ids[i : i + args.batch_size]
        placeholders = ",".join(["%s"] * len(batch))
        sql = (
            "UPDATE demonstration_pool "
            "SET demo_embedding = SNOWFLAKE.CORTEX.EMBED_TEXT_1024(%s, report_text) "
            f"WHERE demo_id IN ({placeholders})"
        )
        cur.execute(sql, [EMBED_MODEL, *batch])
        conn.commit()
        done += len(batch)
        elapsed = time.time() - start
        rate = done / elapsed if elapsed else 0
        eta = (len(demo_ids) - done) / rate if rate else 0
        print(f"  {done}/{len(demo_ids)}  ({rate:.1f} rows/s, eta {eta:.0f}s)")

    cur.execute("SELECT COUNT(*) FROM demonstration_pool WHERE demo_embedding IS NOT NULL")
    with_emb = cur.fetchone()[0]
    print(f"\nDone in {time.time() - start:.1f}s. Demos with embedding: {with_emb}/100")
    conn.close()


if __name__ == "__main__":
    main()
