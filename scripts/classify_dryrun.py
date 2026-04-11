"""Dry-run: classify all existing advisories without writing to DB."""
import json
import os
from collections import Counter, defaultdict

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector

from ingestion.advisory.html_parser import _classify_document_type


def main():
    conn = snowflake.connector.connect(
        account=os.environ["SNOWFLAKE_ACCOUNT"],
        user=os.environ["SNOWFLAKE_USER"],
        password=os.environ["SNOWFLAKE_PASSWORD"],
        database=os.environ["SNOWFLAKE_DATABASE"],
        schema=os.environ["SNOWFLAKE_SCHEMA"],
        warehouse=os.environ["SNOWFLAKE_WAREHOUSE"],
    )
    cur = conn.cursor()
    cur.execute("SELECT advisory_id, title, advisory_type, co_authors FROM advisories")
    rows = cur.fetchall()

    counter = Counter()
    samples = defaultdict(list)

    for advisory_id, title, advisory_type, co_authors_raw in rows:
        if co_authors_raw is None:
            co_authors = []
        elif isinstance(co_authors_raw, list):
            co_authors = co_authors_raw
        else:
            try:
                co_authors = json.loads(co_authors_raw)
            except Exception:
                co_authors = []

        dt = _classify_document_type(title or "", advisory_type or "", co_authors)
        counter[dt] += 1
        if len(samples[dt]) < 5:
            samples[dt].append((advisory_id, (title or "")[:90], len(co_authors)))

    print(f"Total: {len(rows)}\n")
    print("Distribution:")
    for dt, n in counter.most_common():
        print(f"  {dt:16s} {n}")
    print("\nSamples:")
    for dt in counter:
        print(f"[{dt}]")
        for aid, t, nco in samples[dt]:
            print(f"  {aid}  co={nco}  {t}")
        print()


if __name__ == "__main__":
    main()
