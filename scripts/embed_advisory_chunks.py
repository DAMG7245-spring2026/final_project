"""
CLI wrapper for ingestion.advisory.embedder.run_embed_chunks.

Backfill `chunk_embedding` for rows in ADVISORY_CHUNKS using Snowflake Cortex.
Default is dry-run. Pass --write to commit UPDATEs.
"""
import argparse
import json
import logging

from dotenv import load_dotenv

load_dotenv()

from ingestion.advisory.embedder import DEFAULT_CHUNK_BATCH, run_embed_chunks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Commit UPDATEs (default: dry-run)")
    parser.add_argument("--force", action="store_true", help="Re-embed rows that already have an embedding")
    parser.add_argument("--advisory-id", help="Only embed chunks for this advisory_id")
    parser.add_argument("--limit", type=int, help="Only process first N chunks (for testing)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_CHUNK_BATCH)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    stats = run_embed_chunks(
        advisory_id=args.advisory_id,
        force=args.force,
        batch_size=args.batch_size,
        limit=args.limit,
        write=args.write,
    )
    print(json.dumps(stats, indent=2, default=str))


if __name__ == "__main__":
    main()
