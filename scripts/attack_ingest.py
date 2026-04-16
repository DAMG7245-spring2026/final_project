#!/usr/bin/env python3
"""MITRE ATT&CK ingestion CLI (Phase 3)."""

from __future__ import annotations

import argparse
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def main() -> int:
    parser = argparse.ArgumentParser(description="MITRE ATT&CK full ingestion.")
    parser.add_argument(
        "command",
        choices=["sync"],
        help="Run ATT&CK full fetch/transform/load",
    )
    args = parser.parse_args()

    if args.command == "sync":
        from ingestion.attack.pipeline import run_attack_full_reload

        stats = run_attack_full_reload()
        print(f"objects_fetched={stats['objects_fetched']}")
        print(
            "techniques={techniques} actors={actors} mitigations={mitigations} "
            "tactics={tactics} campaigns={campaigns} relationships={relationships}".format(
                **stats
            )
        )
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
