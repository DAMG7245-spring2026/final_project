#!/usr/bin/env python3
"""
CWE catalog: preview transformed rows (no Snowflake), or load to Snowflake.

Replace /path/to/catalog.json with your real CWE JSON path.

  poetry run python scripts/cwe_catalog.py preview /path/to/catalog.json
  # By default writes under project data/:
  #   data/cwe_transformed_preview.json
  #   data/cwe_raw_sample.json
  # Or force the folder explicitly:
  poetry run python scripts/cwe_catalog.py preview /path/to/catalog.json --out-dir data
  poetry run python scripts/cwe_catalog.py load-snowflake --input CATALOG.json
  poetry run python scripts/cwe_catalog.py load-snowflake --from-transformed data/preview.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent


def cmd_preview(args: argparse.Namespace) -> int:
    from ingestion.cwe.transform import (
        raw_weaknesses_sample_document,
        transform_catalog_with_stats,
    )

    catalog = Path(args.catalog).expanduser()
    if not catalog.is_file():
        print(
            f"Catalog file not found: {catalog}\n"
            "Use the real path to your CWE JSON file on disk. "
            "README examples like YOUR_CATALOG.json, /path/to/catalog.json, "
            "or CATALOG.json are placeholders — replace them with your actual path, e.g. "
            "~/Downloads/cwec_v4.16.json or ./data/my_cwe.json",
            file=sys.stderr,
        )
        return 1
    records, stats = transform_catalog_with_stats(catalog)
    to_write = records if args.limit is None else records[: args.limit]

    if args.out_dir:
        out_dir = (
            Path(args.out_dir).expanduser()
            if Path(args.out_dir).expanduser().is_absolute()
            else ROOT / args.out_dir
        )
        out_path = out_dir / "cwe_transformed_preview.json"
        raw_out_override = out_dir / "cwe_raw_sample.json"
    else:
        out_path = Path(args.out).expanduser()
        raw_out_override = None

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "ndjson":
        with out_path.open("w", encoding="utf-8") as f:
            for row in to_write:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
    else:
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(to_write, f, indent=2, ensure_ascii=False)

    if raw_out_override is not None:
        raw_out = raw_out_override
    else:
        raw_out = Path(args.raw_sample_out).expanduser() if args.raw_sample_out else None
    if raw_out is not None and not args.skip_raw_sample:
        raw_out.parent.mkdir(parents=True, exist_ok=True)
        doc = raw_weaknesses_sample_document(catalog, args.raw_sample_limit)
        with raw_out.open("w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)

    print("CWE catalog preview")
    print(f"  outputs_dir:      {out_path.parent.resolve()}")
    print(f"  source:           {catalog}")
    print(f"  raw_weaknesses:   {stats['raw_weaknesses']}")
    print(f"  skipped_deprecated: {stats['skipped_deprecated']}")
    print(f"  skipped_other:    {stats['skipped_other']}")
    print(f"  rows_kept:        {stats['kept']}")
    print(f"  written_to_file:  {len(to_write)} -> {out_path}")
    if raw_out is not None and not args.skip_raw_sample:
        print(
            f"  raw_sample:       first {args.raw_sample_limit} source weaknesses -> {raw_out}"
        )
    if to_write:
        sample = to_write[0]
        print("  sample_row keys: ", ", ".join(sorted(sample.keys())))
        print(f"  sample cwe_id:   {sample.get('cwe_id')}")
        print(f"  sample name:     {(sample.get('name') or '')[:80]}...")
    return 0


def cmd_load_snowflake(args: argparse.Namespace) -> int:
    load_dotenv(ROOT / ".env")
    from ingestion.cwe.loader import load_cwe_records
    from ingestion.cwe.snowflake_load import load_cwe_records_to_snowflake
    from ingestion.cwe.transform import load_transformed_json

    has_in = bool(args.input)
    has_tf = bool(args.from_transformed)
    if has_in == has_tf:
        print(
            "Provide exactly one of --input (catalog JSON) or "
            "--from-transformed (preview JSON array).",
            file=sys.stderr,
        )
        return 1
    if has_tf:
        p = Path(args.from_transformed).expanduser()
        if not p.is_file():
            print(f"File not found: {p}", file=sys.stderr)
            return 1
        records = load_transformed_json(p)
        n = load_cwe_records_to_snowflake(records)
    else:
        p = Path(args.input).expanduser()
        if not p.is_file():
            print(f"Catalog file not found: {p}", file=sys.stderr)
            return 1
        n = load_cwe_records(p)
    print(f"Processed {n} rows (MERGE into cwe_records).")
    return 0


def main() -> int:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description="CWE catalog preview and Snowflake load.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_prev = sub.add_parser(
        "preview",
        help="Transform catalog to JSON/NDJSON; no Snowflake.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Default output directory: <project>/data/\n"
            "  - cwe_transformed_preview.json\n"
            "  - cwe_raw_sample.json\n"
            "Use --out-dir data to force that folder explicitly."
        ),
    )
    p_prev.add_argument("catalog", type=str, help="Path to CWE catalog JSON")
    p_prev.add_argument(
        "--out-dir",
        type=str,
        default=None,
        metavar="DIR",
        help=(
            "Put both outputs in DIR: cwe_transformed_preview.json + cwe_raw_sample.json "
            "(relative paths are under project root). Overrides --out/--raw-sample-out."
        ),
    )
    p_prev.add_argument(
        "--out",
        type=str,
        default=str(ROOT / "data" / "cwe_transformed_preview.json"),
        help="Transformed JSON output path (default: <project>/data/cwe_transformed_preview.json)",
    )
    p_prev.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Write only first N rows (full parse still runs for stats)",
    )
    p_prev.add_argument(
        "--format",
        choices=("json", "ndjson"),
        default="json",
        help="Output format",
    )
    p_prev.add_argument(
        "--raw-sample-out",
        type=str,
        default=str(ROOT / "data" / "cwe_raw_sample.json"),
        help="Also write first N source weaknesses (untransformed) for comparison",
    )
    p_prev.add_argument(
        "--raw-sample-limit",
        type=int,
        default=10,
        help="How many raw weakness objects to include in raw sample file",
    )
    p_prev.add_argument(
        "--skip-raw-sample",
        action="store_true",
        help="Do not write the raw source sample file",
    )
    p_prev.set_defaults(func=cmd_preview)

    p_load = sub.add_parser(
        "load-snowflake",
        help="MERGE transformed rows into Snowflake cwe_records (requires .env).",
    )
    p_load.add_argument(
        "--input",
        type=str,
        default=None,
        help="Path to original CWE catalog JSON (transformed in-process)",
    )
    p_load.add_argument(
        "--from-transformed",
        type=str,
        default=None,
        help="Path to JSON array from preview step",
    )
    p_load.set_defaults(func=cmd_load_snowflake)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
