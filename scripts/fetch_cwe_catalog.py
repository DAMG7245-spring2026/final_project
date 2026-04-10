#!/usr/bin/env python3
"""
Download MITRE CWE v4.16 XML (official), unzip to data/, convert to JSON catalog for preview/load.

  poetry run python scripts/fetch_cwe_catalog.py
  poetry run python scripts/fetch_cwe_catalog.py --skip-download   # use existing zip/xml

Writes:
  data/cwec_v4.16.xml.zip   (from MITRE, if downloaded)
  data/cwec_v4.16.xml       (extracted)
  data/cwec_catalog.json    (weaknesses[] for cwe_catalog.py preview)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_v4.16.xml.zip"
ZIP_NAME = "cwec_v4.16.xml.zip"
CATALOG_JSON = "cwec_catalog.json"


def main() -> int:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description="Fetch MITRE CWE catalog into data/.")
    parser.add_argument(
        "--skip-download",
        action="store_true",
        help="Skip HTTP download; expect zip or xml already under data/",
    )
    parser.add_argument(
        "--url",
        default=ZIP_URL,
        help="Override CWE XML zip URL",
    )
    args = parser.parse_args()

    zip_path = DATA / ZIP_NAME

    if not args.skip_download:
        print(f"Downloading {args.url} ...")
        DATA.mkdir(parents=True, exist_ok=True)
        with httpx.Client(follow_redirects=True, timeout=120.0) as client:
            r = client.get(args.url)
            r.raise_for_status()
            zip_path.write_bytes(r.content)
        print(f"  saved {zip_path} ({len(r.content) // 1024} KiB)")

    if not zip_path.is_file():
        print(f"Missing zip: {zip_path}", file=sys.stderr)
        return 1

    from ingestion.cwe.xml_catalog import convert_cwec_xml_file_to_catalog_json, extract_xml_from_zip

    print(f"Extracting {zip_path.name} ...")
    xml_path = extract_xml_from_zip(zip_path, DATA)
    print(f"  xml: {xml_path}")

    json_path = DATA / CATALOG_JSON
    print(f"Converting to {json_path.name} ...")
    doc = convert_cwec_xml_file_to_catalog_json(xml_path, json_path)
    n = len(doc["weaknesses"])
    print(f"  weaknesses: {n}")
    print("Done. Preview with:")
    print(f"  poetry run python scripts/cwe_catalog.py preview {json_path} --out-dir data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
