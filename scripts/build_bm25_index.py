"""Build the BM25 index over advisory_chunks.chunk_text and pickle it.

Usage:
    python scripts/build_bm25_index.py               # default path data/bm25_index.pkl
    python scripts/build_bm25_index.py --output foo.pkl
    python scripts/build_bm25_index.py --force       # rebuild even if cache exists

Invoked automatically at FastAPI startup (see app/main.py lifespan),
but also safe to run manually after a re-chunk / re-ingest.
"""
import argparse
import logging
import sys

from dotenv import load_dotenv

load_dotenv()

from app.services.bm25_index import (
    DEFAULT_INDEX_PATH,
    BM25Index,
    load_or_build_bm25_index,
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
        index = BM25Index.build_from_snowflake()
        index.save(args.output)
    else:
        index = load_or_build_bm25_index(path=args.output)

    print(
        f"[bm25] ready: {index.num_docs} docs indexed -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
