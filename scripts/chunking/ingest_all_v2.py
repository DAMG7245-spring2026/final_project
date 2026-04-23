"""
CLI wrapper for ingestion.advisory.chunk_loader.run_chunk_all.

Bulk re-chunk every advisory in S3 with chunker_v2 and write to ADVISORY_CHUNKS.
Default is dry-run. Pass --commit to actually write.

Note: chunk_embedding is NOT preserved — must re-run embedding pipeline after.
"""
import argparse
import json
import logging
import sys

from dotenv import load_dotenv

load_dotenv()

from ingestion.advisory.chunk_loader import run_chunk_all


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", dest="only_type", help="only this document_type")
    parser.add_argument("--limit", type=int, default=None, help="limit advisories (debug)")
    parser.add_argument("--commit", action="store_true", help="actually write (default: dry-run)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        stats = run_chunk_all(
            only_type=args.only_type,
            limit=args.limit,
            commit=args.commit,
        )
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(stats, indent=2, default=str))
    if stats.get("dry_run"):
        print("\n[dry-run] zero DB writes. Rerun with --commit to actually write.")
    else:
        print("\nNOTE: chunk_embedding was wiped. Re-run scripts/embed_advisory_chunks.py.")


if __name__ == "__main__":
    main()
