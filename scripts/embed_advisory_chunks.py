"""
Backfill `chunk_embedding` for rows in ADVISORY_CHUNKS using Snowflake Cortex.

Model: snowflake-arctic-embed-l-v2.0  (1024-dim, 8192 token context)
Runs entirely server-side — chunk_text never leaves Snowflake.

Default is dry-run (shows what would be embedded). Pass --write to commit.
"""
import argparse
import time

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector

from app.config import get_settings


EMBED_MODEL = "snowflake-arctic-embed-l-v2.0"
BATCH_SIZE = 200


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Commit UPDATEs (default: dry-run)")
    parser.add_argument("--force", action="store_true", help="Re-embed rows that already have an embedding")
    parser.add_argument("--advisory-id", help="Only embed chunks for this advisory_id")
    parser.add_argument("--limit", type=int, help="Only process first N chunks (for testing)")
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

    where = []
    params: list = []
    if not args.force:
        where.append("chunk_embedding IS NULL")
    if args.advisory_id:
        where.append("advisory_id = %s")
        params.append(args.advisory_id)
    where.append("chunk_text IS NOT NULL")
    where_sql = " AND ".join(where)

    cur.execute(
        f"SELECT COUNT(*), COALESCE(MAX(token_count),0), COALESCE(AVG(token_count),0)::INT "
        f"FROM advisory_chunks WHERE {where_sql}",
        params,
    )
    total, max_tok, avg_tok = cur.fetchone()
    if args.limit:
        total = min(total, args.limit)
    print(f"Target: {total} chunks   max_tokens={max_tok}  avg_tokens={avg_tok}")
    print(f"Model:  {EMBED_MODEL}  (1024-dim)")

    if total == 0:
        print("Nothing to embed.")
        return

    limit_sql = f" LIMIT {args.limit}" if args.limit else ""
    cur.execute(
        f"SELECT chunk_id FROM advisory_chunks WHERE {where_sql} ORDER BY chunk_id{limit_sql}",
        params,
    )
    chunk_ids = [row[0] for row in cur.fetchall()]

    if not args.write:
        print(f"\n[dry-run] Would embed {len(chunk_ids)} chunks in batches of {args.batch_size}.")
        print("Rerun with --write to commit.")
        return

    print(f"\nEmbedding {len(chunk_ids)} chunks in batches of {args.batch_size}...")
    start = time.time()
    done = 0
    for i in range(0, len(chunk_ids), args.batch_size):
        batch = chunk_ids[i : i + args.batch_size]
        placeholders = ",".join(["%s"] * len(batch))
        sql = (
            "UPDATE advisory_chunks "
            "SET chunk_embedding = SNOWFLAKE.CORTEX.EMBED_TEXT_1024(%s, chunk_text) "
            f"WHERE chunk_id IN ({placeholders})"
        )
        cur.execute(sql, [EMBED_MODEL, *batch])
        conn.commit()
        done += len(batch)
        elapsed = time.time() - start
        rate = done / elapsed if elapsed else 0
        eta = (len(chunk_ids) - done) / rate if rate else 0
        print(f"  {done}/{len(chunk_ids)}  ({rate:.1f} rows/s, eta {eta:.0f}s)")

    cur.execute(
        "SELECT COUNT(*) FROM advisory_chunks WHERE chunk_embedding IS NOT NULL"
    )
    (with_emb,) = cur.fetchone()
    print(f"\nDone in {time.time()-start:.1f}s. Total rows with embeddings: {with_emb}")


if __name__ == "__main__":
    main()
