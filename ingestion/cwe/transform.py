"""Parse MITRE-style CWE catalog JSON and map rows to cwe_records shape (no I/O to Snowflake)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator


def normalize_description(desc: Any) -> str:
    if desc is None:
        return ""
    if isinstance(desc, str):
        return desc.strip()
    if isinstance(desc, dict):
        for key in ("#text", "text", "content", "value"):
            val = desc.get(key)
            if isinstance(val, str):
                return val.strip()
        for val in desc.values():
            if isinstance(val, str) and val.strip():
                return val.strip()
        try:
            return json.dumps(desc, ensure_ascii=False)[:16000]
        except (TypeError, ValueError):
            return str(desc)[:16000]
    return str(desc).strip()


def format_cwe_id(raw: Any) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, int):
        return f"CWE-{raw}"
    s = str(raw).strip()
    up = s.upper()
    if up.startswith("CWE-"):
        rest = s[4:].strip().lstrip("-")
        if not rest:
            return None
        return f"CWE-{rest}"
    try:
        return f"CWE-{int(s, 10)}"
    except ValueError:
        return f"CWE-{s}" if s else None


def weakness_to_record(w: dict[str, Any]) -> dict[str, Any] | None:
    """
    Map one catalog weakness object to a cwe_records-shaped dict.
    Returns None if skipped (deprecated or missing id).
    """
    status = (w.get("Status") or "").strip()
    if status == "Deprecated":
        return None
    cwe_id = format_cwe_id(w.get("CWE_ID", w.get("ID")))
    if not cwe_id:
        return None
    name = (w.get("Name") or "")[:300]
    abstraction = (w.get("Abstraction") or "")[:20]
    description = normalize_description(w.get("Description"))[:16000]
    return {
        "cwe_id": cwe_id,
        "name": name,
        "abstraction": abstraction,
        "status": status[:30] if status else "",
        "description": description,
        "is_deprecated": False,
    }


def extract_weaknesses(data: dict[str, Any]) -> list[dict[str, Any]]:
    weaknesses = data.get("weaknesses")
    if isinstance(weaknesses, list):
        return [x for x in weaknesses if isinstance(x, dict)]
    for _k, v in data.items():
        if (
            isinstance(v, list)
            and v
            and isinstance(v[0], dict)
            and ("CWE_ID" in v[0] or "ID" in v[0])
        ):
            return [x for x in v if isinstance(x, dict)]
    raise ValueError(
        "Catalog JSON must contain a top-level 'weaknesses' array "
        "or a list of objects with CWE_ID/ID."
    )


def build_records_and_stats(
    data: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Single pass: produce cwe_records-shaped rows and parse statistics."""
    raw = 0
    skipped_deprecated = 0
    skipped_other = 0
    records: list[dict[str, Any]] = []
    for w in extract_weaknesses(data):
        raw += 1
        status = (w.get("Status") or "").strip()
        if status == "Deprecated":
            skipped_deprecated += 1
            continue
        rec = weakness_to_record(w)
        if rec is None:
            skipped_other += 1
            continue
        records.append(rec)
    stats = {
        "raw_weaknesses": raw,
        "kept": len(records),
        "skipped_deprecated": skipped_deprecated,
        "skipped_other": skipped_other,
    }
    return records, stats


def iter_cwe_records_from_catalog(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield transformed records (single pass over build_records_and_stats)."""
    records, _ = build_records_and_stats(data)
    yield from records


def load_catalog_document(path: Path | str) -> dict[str, Any]:
    """Load the catalog JSON root object from disk."""
    p = Path(path)
    with p.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Catalog JSON root must be an object.")
    return data


def raw_weaknesses_sample_document(
    path: Path | str, limit: int
) -> dict[str, Any]:
    """
    Build a small JSON document with the first `limit` weakness objects
    exactly as they appear in the source catalog (before transform).
    For side-by-side comparison with transformed preview output.
    """
    p = Path(path).resolve()
    data = load_catalog_document(p)
    weaknesses = extract_weaknesses(data)
    lim = max(0, min(limit, len(weaknesses)))
    return {
        "_note": (
            "Subset of source catalog weaknesses[] before transform. "
            "Compare to cwe_transformed_preview.json rows."
        ),
        "source_catalog": str(p),
        "sample_count": lim,
        "total_weaknesses_in_file": len(weaknesses),
        "weaknesses": weaknesses[:lim],
    }


def transform_catalog_to_records(path: Path | str) -> list[dict[str, Any]]:
    """Load catalog JSON from disk and return all non-deprecated cwe_records-shaped rows."""
    data = load_catalog_document(path)
    records, _stats = build_records_and_stats(data)
    return records


def transform_catalog_with_stats(
    path: Path | str,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Load catalog from disk; return (records, stats) in one parse."""
    data = load_catalog_document(path)
    return build_records_and_stats(data)


def load_transformed_json(path: Path | str) -> list[dict[str, Any]]:
    """Load a JSON array of row dicts produced by preview (for load-snowflake --from-transformed)."""
    p = Path(path)
    with p.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Transformed JSON must be a JSON array of objects.")
    out: list[dict[str, Any]] = []
    for i, row in enumerate(data):
        if not isinstance(row, dict):
            raise ValueError(f"Item {i} is not an object.")
        if "cwe_id" not in row:
            raise ValueError(f"Item {i} missing cwe_id.")
        out.append(
            {
                "cwe_id": str(row["cwe_id"])[:20],
                "name": str(row.get("name", ""))[:300],
                "abstraction": str(row.get("abstraction", ""))[:20],
                "status": str(row.get("status", ""))[:30],
                "description": str(row.get("description", ""))[:16000],
                "is_deprecated": bool(row.get("is_deprecated", False)),
            }
        )
    return out
