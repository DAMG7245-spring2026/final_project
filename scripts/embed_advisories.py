"""
Step 1-2: Compute report_embedding for all advisories using Snowflake Cortex.

Concatenates advisory_chunks in order to form report_text, then embeds with
snowflake-arctic-embed-l-v2.0 (1024-dim). Reports longer than 8192 tokens
are automatically truncated by Cortex.

Usage:
  poetry run python scripts/embed_advisories.py              # dry-run
  poetry run python scripts/embed_advisories.py --write      # actually embed
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

    # Only embed advisories that have chunks
    where = "EXISTS (SELECT 1 FROM advisory_chunks c WHERE c.advisory_id = a.advisory_id)"
    if not args.force:
        where += " AND a.report_embedding IS NULL"

    cur.execute(f"SELECT COUNT(*) FROM advisories a WHERE {where}")
    total = cur.fetchone()[0]
    print(f"Target : {total} advisories")
    print(f"Model  : {EMBED_MODEL}  (1024-dim)")
    print(f"Batch  : {args.batch_size}")

    if total == 0:
        print("Nothing to embed.")
        conn.close()
        return

    cur.execute(f"SELECT advisory_id FROM advisories a WHERE {where} ORDER BY advisory_id")
    advisory_ids = [row[0] for row in cur.fetchall()]

    if not args.write:
        print(f"\n[dry-run] Would embed {len(advisory_ids)} advisories in batches of {args.batch_size}.")
        print("Rerun with --write to commit.")
        conn.close()
        return

    print(f"\nEmbedding {len(advisory_ids)} advisories...")
    start = time.time()
    done = 0

    for i in range(0, len(advisory_ids), args.batch_size):
        batch = advisory_ids[i : i + args.batch_size]
        placeholders = ",".join(["%s"] * len(batch))
        # Concat chunks server-side, then embed
        sql = f"""
            UPDATE advisories a
            SET report_embedding = SNOWFLAKE.CORTEX.EMBED_TEXT_1024(
                %s,
                (
                    SELECT LISTAGG(c.chunk_text, '\n\n') WITHIN GROUP (ORDER BY c.chunk_index)
                    FROM advisory_chunks c
                    WHERE c.advisory_id = a.advisory_id
                )
            )
            WHERE a.advisory_id IN ({placeholders})
        """
        cur.execute(sql, [EMBED_MODEL, *batch])
        conn.commit()
        done += len(batch)
        elapsed = time.time() - start
        rate = done / elapsed if elapsed else 0
        eta = (len(advisory_ids) - done) / rate if rate else 0
        print(f"  {done}/{len(advisory_ids)}  ({rate:.1f} rows/s, eta {eta:.0f}s)")

    cur.execute("SELECT COUNT(*) FROM advisories WHERE report_embedding IS NOT NULL")
    with_emb = cur.fetchone()[0]
    print(f"\nDone in {time.time() - start:.1f}s. Advisories with embedding: {with_emb}/302")
    conn.close()


if __name__ == "__main__":
    main()
