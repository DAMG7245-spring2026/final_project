#!/usr/bin/env python3
"""CISA KEV ingestion CLI (Phase 4)."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="CISA KEV sync.")
    parser.add_argument(
        "command",
        choices=["sync"],
        help="Run KEV fetch + enrichment + queue upsert",
    )
    args = parser.parse_args()

    if args.command == "sync":
        from ingestion.kev.enricher import run_kev_sync

        stats = run_kev_sync()
        print(f"run_id={stats['run_id']}")
        print(f"mode={stats['mode']}")
        print(
            "feed_size={feed_size} deduped_rows={deduped_rows} "
            "existing_count={existing_count} missing_count={missing_count} elapsed_sec={elapsed_sec:.3f}".format(
                **stats
            )
        )
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
