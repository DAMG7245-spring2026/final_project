"""
CLI wrapper for ingestion.advisory.classifier.run_backfill_document_type.

Default is dry-run. Pass --write to commit UPDATEs.
"""
import argparse
import json
import logging

from dotenv import load_dotenv

load_dotenv()

from ingestion.advisory.classifier import run_backfill_document_type


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Commit UPDATEs (default: dry-run)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    stats = run_backfill_document_type(write=args.write)
    print(json.dumps(stats, indent=2, default=str))


if __name__ == "__main__":
    main()
