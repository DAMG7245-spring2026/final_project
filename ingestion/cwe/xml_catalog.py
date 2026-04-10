"""Convert MITRE cwec_*.xml (schema v7) to a JSON object with weaknesses[] for transform.py."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

CWE_NS = "http://cwe.mitre.org/cwe-7"


def _q(tag: str) -> str:
    return f"{{{CWE_NS}}}{tag}"


def _element_text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def weaknesses_dicts_from_xml_tree(root: ET.Element) -> list[dict[str, Any]]:
    weaknesses_el = root.find(_q("Weaknesses"))
    if weaknesses_el is None:
        raise ValueError("CWE XML: missing <Weaknesses> (wrong namespace or file).")
    rows: list[dict[str, Any]] = []
    for w in weaknesses_el.findall(_q("Weakness")):
        wid = w.get("ID")
        if not wid:
            continue
        try:
            cwe_id = int(wid, 10)
        except ValueError:
            continue
        rows.append(
            {
                "CWE_ID": cwe_id,
                "Name": (w.get("Name") or "")[:500],
                "Abstraction": (w.get("Abstraction") or "")[:100],
                "Status": (w.get("Status") or "")[:100],
                "Description": _element_text(w.find(_q("Description")))[:32000],
            }
        )
    return rows


def convert_cwec_xml_file_to_catalog_json(
    xml_path: Path | str, json_path: Path | str
) -> dict[str, Any]:
    """Parse cwec XML, write {\"weaknesses\": [...]} to json_path. Returns the document."""
    p = Path(xml_path)
    tree = ET.parse(p)
    root = tree.getroot()
    weaknesses = weaknesses_dicts_from_xml_tree(root)
    doc = {
        "_source": str(p.resolve()),
        "_format": "converted_from_mitre_cwec_xml",
        "weaknesses": weaknesses,
    }
    out = Path(json_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return doc


def extract_xml_from_zip(zip_path: Path | str, dest_dir: Path | str) -> Path:
    """Unzip first .xml member into dest_dir; return path to extracted file."""
    zpath = Path(zip_path)
    d = Path(dest_dir)
    d.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zpath, "r") as zf:
        names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
        if not names:
            raise ValueError("ZIP contains no .xml file.")
        member = names[0]
        zf.extract(member, d)
        return d / member
