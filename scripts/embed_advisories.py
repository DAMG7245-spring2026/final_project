"""
CLI wrapper for ingestion.advisory.embedder.run_embed_reports.

Compute report_embedding for all advisories using Snowflake Cortex
(LISTAGG chunks → EMBED_TEXT_1024).

Default is dry-run. Pass --write to commit UPDATEs.
"""
import argparse
import json
import logging

from dotenv import load_dotenv

load_dotenv()

from ingestion.advisory.embedder import DEFAULT_REPORT_BATCH, run_embed_reports


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Commit UPDATEs (default: dry-run)")
    parser.add_argument("--force", action="store_true", help="Re-embed rows that already have an embedding")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_REPORT_BATCH)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    stats = run_embed_reports(
        force=args.force,
        batch_size=args.batch_size,
        write=args.write,
    )
    print(json.dumps(stats, indent=2, default=str))


if __name__ == "__main__":
    main()
