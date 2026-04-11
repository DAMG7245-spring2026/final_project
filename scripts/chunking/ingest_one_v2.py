"""
One-off: re-chunk a single advisory with chunker_v2 and write to ADVISORY_CHUNKS.

WRITE SCRIPT. Deletes existing chunks for the target advisory, then inserts new ones.
section_name holds canonical category; raw sub-heading goes into the sub_section column.

Default target: ar25-218a (SharePoint MAR).
"""
import argparse
import json

from dotenv import load_dotenv

load_dotenv()

import boto3
import snowflake.connector

from app.config import get_settings
from ingestion.advisory.chunker_v2 import chunk_advisory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--advisory-id", default="ar25-218a")
    parser.add_argument("--commit", action="store_true", help="Actually write (default: dry-run)")
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
    cur.execute(
        "SELECT advisory_id, document_type, s3_raw_path, title "
        "FROM advisories WHERE advisory_id = %s",
        (args.advisory_id,),
    )
    row = cur.fetchone()
    if not row:
        raise SystemExit(f"advisory not found: {args.advisory_id}")

    advisory_id, document_type, s3_path, title = row
    print(f"Target : {advisory_id}  [{document_type}]")
    print(f"Title  : {(title or '')[:80]}")
    print(f"S3 path: {s3_path}")

    cur.execute(
        "SELECT COUNT(*) FROM advisory_chunks WHERE advisory_id = %s",
        (advisory_id,),
    )
    old_count = cur.fetchone()[0]
    print(f"\nExisting chunks: {old_count}")

    obj = s3.get_object(Bucket=s.s3_bucket, Key=s3_path)
    html = obj["Body"].read().decode("utf-8", errors="replace")

    chunks = chunk_advisory(advisory_id, document_type, html)
    print(f"New chunks    : {len(chunks)}")

    # Preview
    print("\nNew chunk outline:")
    for c in chunks:
        sub = (c.sub_section or "")[:50]
        print(f"  [{c.chunk_index:02d}] {c.section_name:<22} {sub:<52} {c.token_count:>5}t")

    if not args.commit:
        print("\n[dry-run] rerun with --commit to actually write.")
        return

    print("\n>>> DELETING existing chunks...")
    cur.execute("DELETE FROM advisory_chunks WHERE advisory_id = %s", (advisory_id,))
    print(f"    deleted {cur.rowcount}")

    print(">>> INSERTING new chunks...")
    insert_sql = """
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
    for c in chunks:
        sub = (c.sub_section or None)
        if sub and len(sub) > 200:
            sub = sub[:200]
        cur.execute(insert_sql, (
            c.chunk_id, c.advisory_id, c.chunk_index, c.section_name, sub,
            c.chunk_text, c.token_count, c.content_hash,
            json.dumps(c.cve_ids), json.dumps(c.cwe_ids), json.dumps(c.mitre_tech_ids),
        ))
    conn.commit()
    print(f"    inserted {len(chunks)}")

    cur.execute(
        "SELECT COUNT(*) FROM advisory_chunks WHERE advisory_id = %s",
        (advisory_id,),
    )
    print(f"\nFinal chunk count for {advisory_id}: {cur.fetchone()[0]}")

    conn.close()


if __name__ == "__main__":
    main()
