"""
Dry-run the per-type chunker v2 on every advisory in S3.

READ-ONLY. No DB writes. Reports:
  - per document_type: advisory count, total chunks, avg/median/max tokens,
    section distribution, sub-section rate
  - vs current ADVISORY_CHUNKS: chunk count diff per advisory
  - sample chunks for manual inspection
"""
import argparse
import statistics
from collections import Counter, defaultdict

from dotenv import load_dotenv

load_dotenv()

import boto3
import snowflake.connector

from app.config import get_settings
from ingestion.advisory.chunker_v2 import chunk_advisory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Limit advisories (debug)")
    parser.add_argument("--type", dest="only_type", help="Only this document_type")
    parser.add_argument("--samples", type=int, default=1, help="Sample chunks per type to print")
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
    sql = """
        SELECT a.advisory_id, a.document_type, a.s3_raw_path, a.title,
               COALESCE(c.n, 0) AS old_chunks
        FROM advisories a
        LEFT JOIN (
            SELECT advisory_id, COUNT(*) AS n
            FROM advisory_chunks
            GROUP BY advisory_id
        ) c ON c.advisory_id = a.advisory_id
        WHERE a.s3_raw_path IS NOT NULL
    """
    params = []
    if args.only_type:
        sql += " AND a.document_type = %s"
        params.append(args.only_type)
    sql += " ORDER BY a.document_type, a.published_date DESC"
    cur.execute(sql, params)
    rows = cur.fetchall()
    if args.limit:
        rows = rows[: args.limit]
    print(f"Processing {len(rows)} advisories\n")

    per_type_tokens: dict[str, list[int]] = defaultdict(list)
    per_type_chunks: dict[str, int] = defaultdict(int)
    per_type_advisories: dict[str, int] = defaultdict(int)
    per_type_sections: dict[str, Counter] = defaultdict(Counter)
    per_type_sub_rate: dict[str, list[int]] = defaultdict(list)
    per_type_old_vs_new: dict[str, list[tuple[int, int]]] = defaultdict(list)
    per_type_samples: dict[str, list] = defaultdict(list)
    errors = 0

    for i, (aid, dt, path, title, old_n) in enumerate(rows, 1):
        try:
            obj = s3.get_object(Bucket=s.s3_bucket, Key=path)
            html = obj["Body"].read().decode("utf-8", errors="replace")
        except Exception as e:
            print(f"  ! S3 error {aid}: {e}")
            errors += 1
            continue

        chunks = chunk_advisory(aid, dt or "CSA", html)

        per_type_advisories[dt] += 1
        per_type_chunks[dt] += len(chunks)
        per_type_old_vs_new[dt].append((old_n, len(chunks)))
        for c in chunks:
            per_type_tokens[dt].append(c.token_count)
            per_type_sections[dt][c.section_name] += 1
            per_type_sub_rate[dt].append(1 if c.sub_section else 0)

        if len(per_type_samples[dt]) < args.samples and chunks:
            per_type_samples[dt].append((aid, title, chunks))

        if i % 25 == 0:
            print(f"  progress {i}/{len(rows)}")

    print(f"\n{'='*80}\nPER-TYPE SUMMARY\n{'='*80}")
    for dt in sorted(per_type_advisories):
        toks = per_type_tokens[dt]
        n_adv = per_type_advisories[dt]
        n_chunks = per_type_chunks[dt]
        sub_rate = (sum(per_type_sub_rate[dt]) / len(per_type_sub_rate[dt]) * 100) if per_type_sub_rate[dt] else 0
        diffs = [new - old for (old, new) in per_type_old_vs_new[dt]]
        print(f"\n{dt}")
        print(f"  advisories          : {n_adv}")
        print(f"  total chunks (new)  : {n_chunks}")
        print(f"  avg chunks/advisory : {n_chunks / n_adv:.1f}")
        print(f"  tokens avg/med/max  : {statistics.mean(toks):.0f} / "
              f"{statistics.median(toks):.0f} / {max(toks)}")
        print(f"  sub_section rate    : {sub_rate:.0f}%")
        print(f"  vs old chunker (new-old) avg/median: "
              f"{statistics.mean(diffs):+.1f} / {statistics.median(diffs):+.0f}")
        print(f"  section distribution: "
              f"{dict(per_type_sections[dt].most_common())}")

    print(f"\n{'='*80}\nSAMPLE CHUNKS\n{'='*80}")
    for dt, samples in per_type_samples.items():
        for aid, title, chunks in samples:
            print(f"\n--- {dt} / {aid} :: {(title or '')[:70]} ---")
            print(f"  {len(chunks)} chunks")
            for c in chunks[:4]:
                sub = f" / {c.sub_section[:40]}" if c.sub_section else ""
                preview = c.chunk_text[:160].replace("\n", " ")
                print(f"  [{c.chunk_index:02d}] {c.section_name}{sub}  ({c.token_count}t)")
                print(f"       {preview}...")

    if errors:
        print(f"\n{errors} S3 errors (skipped)")

    print("\n[dry-run] Zero DB writes.")
    conn.close()


if __name__ == "__main__":
    main()
