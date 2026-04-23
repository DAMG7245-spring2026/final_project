"""
CLI wrapper for ingestion.advisory.chunk_loader.run_chunk_advisory.

One-off: re-chunk a single advisory with chunker_v2 and write to ADVISORY_CHUNKS.
Default is dry-run. Pass --commit to actually write.
"""
import argparse
import json
import logging

from dotenv import load_dotenv

load_dotenv()

from ingestion.advisory.chunk_loader import run_chunk_advisory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--advisory-id", default="ar25-218a")
    parser.add_argument("--commit", action="store_true", help="Actually write (default: dry-run)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    stats = run_chunk_advisory(advisory_id=args.advisory_id, commit=args.commit)
    print(json.dumps(stats, indent=2, default=str))


if __name__ == "__main__":
    main()
