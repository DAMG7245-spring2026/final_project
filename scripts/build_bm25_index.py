"""CLI wrapper for app.services.bm25_index — build or refresh the BM25 pickle.

Usage:
    python scripts/build_bm25_index.py               # load cache if present, else build
    python scripts/build_bm25_index.py --output foo.pkl
    python scripts/build_bm25_index.py --force       # rebuild from Snowflake unconditionally

Invoked automatically at FastAPI startup (see app/main.py lifespan),
and also wired as the final task of ``advisory_weekly_dag``.
"""
import argparse
import json
import logging
import sys

from dotenv import load_dotenv

load_dotenv()

from app.services.bm25_index import (
    DEFAULT_INDEX_PATH,
    load_or_build_bm25_index,
    rebuild_bm25_index,
)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=DEFAULT_INDEX_PATH)
    parser.add_argument(
        "--force",
        action="store_true",
        help="rebuild from Snowflake even if pickle cache exists",
    )
    args = parser.parse_args()

    if args.force:
        stats = rebuild_bm25_index(path=args.output)
        print(json.dumps(stats, indent=2, default=str))
    else:
        index = load_or_build_bm25_index(path=args.output)
        print(f"[bm25] ready: {index.num_docs} docs indexed -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
