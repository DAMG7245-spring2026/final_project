"""
Bulk re-chunk every advisory in S3 with chunker_v2 and write to ADVISORY_CHUNKS.

WRITE SCRIPT. For each advisory:
  1. DELETE existing chunks (including any chunk_embedding)
  2. INSERT fresh v2 chunks via executemany
  3. commit per-advisory

Default is dry-run. Use --commit to actually write.
On any error: STOP immediately (no skip-and-continue).

Note: chunk_embedding is NOT preserved — must re-run embedding pipeline after.
"""
import argparse
import json
import sys
import time

from dotenv import load_dotenv

load_dotenv()

import boto3
import snowflake.connector

from app.config import get_settings
from ingestion.advisory.chunker_v2 import chunk_advisory


INSERT_SQL = """
    INSERT INTO advisory_chunks
        (chunk_id, advisory_id, chunk_index, section_name, sub_section,
         chunk_text, token_count, content_hash,
         cve_ids, cwe_ids, mitre_tech_ids)
    SELECT %s, %s, %s, %s, %s,
           %s, %s, %s,
           PARSE_JSON(%s)::ARRAY,
           PARSE_JSON(%s)::ARRAY,
           PARSE_JSON(%s)::ARRAY
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", dest="only_type", help="only this document_type")
    parser.add_argument("--limit", type=int, default=None, help="limit advisories (debug)")
    parser.add_argument("--commit", action="store_true", help="actually write (default: dry-run)")
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
    s3 = boto3.client(
        "s3",
        aws_access_key_id=s.aws_access_key_id,
        aws_secret_access_key=s.aws_secret_access_key,
        region_name=s.aws_region,
    )

    cur = conn.cursor()
    sql = (
        "SELECT advisory_id, document_type, s3_raw_path, title "
        "FROM advisories "
        "WHERE s3_raw_path IS NOT NULL AND document_type IS NOT NULL"
    )
    params: list = []
    if args.only_type:
        sql += " AND document_type = %s"
        params.append(args.only_type)
    sql += " ORDER BY document_type, published_date DESC NULLS LAST"
    cur.execute(sql, params)
    rows = cur.fetchall()
    if args.limit:
        rows = rows[: args.limit]

    mode = "COMMIT" if args.commit else "DRY-RUN"
    print(f"[{mode}] processing {len(rows)} advisories")
    if args.only_type:
        print(f"        filter: document_type = {args.only_type}")
    print()

    total_deleted = 0
    total_inserted = 0
    t0 = time.time()

    for i, (advisory_id, document_type, s3_path, title) in enumerate(rows, 1):
        try:
            obj = s3.get_object(Bucket=s.s3_bucket, Key=s3_path)
            html = obj["Body"].read().decode("utf-8", errors="replace")

            chunks = chunk_advisory(advisory_id, document_type, html)
            if not chunks:
                raise RuntimeError(f"zero chunks produced for {advisory_id}")

            max_tok = max(c.token_count for c in chunks)
            print(
                f"  [{i:3d}/{len(rows)}] {advisory_id:<14} {document_type:<15} "
                f"{len(chunks):3d} chunks  max={max_tok:>4}t  :: {(title or '')[:50]}"
            )

            if not args.commit:
                continue

            cur.execute(
                "DELETE FROM advisory_chunks WHERE advisory_id = %s",
                (advisory_id,),
            )
            deleted = cur.rowcount
            total_deleted += deleted

            for c in chunks:
                sub = c.sub_section
                if sub and len(sub) > 200:
                    sub = sub[:200]
                cur.execute(INSERT_SQL, (
                    c.chunk_id, c.advisory_id, c.chunk_index, c.section_name, sub,
                    c.chunk_text, c.token_count, c.content_hash,
                    json.dumps(c.cve_ids), json.dumps(c.cwe_ids), json.dumps(c.mitre_tech_ids),
                ))
            conn.commit()
            total_inserted += len(chunks)

        except Exception as e:
            conn.rollback()
            print(f"\n!! FAILED on {advisory_id}: {type(e).__name__}: {e}")
            print(f"   processed {i - 1}/{len(rows)} before failure")
            print(f"   total deleted so far: {total_deleted}")
            print(f"   total inserted so far: {total_inserted}")
            conn.close()
            sys.exit(1)

    elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print(f"[{mode}] done. {len(rows)} advisories in {elapsed:.1f}s "
          f"({elapsed / max(len(rows), 1):.2f}s each)")
    if args.commit:
        print(f"         deleted {total_deleted} old chunks")
        print(f"         inserted {total_inserted} new chunks")
        print("\nNOTE: chunk_embedding was wiped. Re-run embedding pipeline.")
    else:
        print("         [dry-run] zero DB writes. Rerun with --commit to actually write.")
    conn.close()


if __name__ == "__main__":
    main()
