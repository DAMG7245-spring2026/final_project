"""Advisory HTML fetch endpoint.

Serves the raw CISA advisory HTML that the ingestion pipeline uploads to
``s3://{S3_BUCKET}/raw/advisories/{advisory_id}.html``. Fronts S3 so the
Streamlit UI doesn't need AWS credentials.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Path
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.services.s3_storage import get_s3_storage
from app.services.snowflake import get_snowflake_service

router = APIRouter(prefix="/advisory", tags=["Advisory"])

# advisory_id shape (CISA): aa23-131a / ar25-012 / ir25-010 etc. Allow lower
# alnum + hyphens only to avoid path-traversal via the S3 key.
_ADVISORY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _validate_advisory_id(advisory_id: str) -> str:
    aid = advisory_id.strip().lower()
    if not _ADVISORY_ID_RE.match(aid):
        raise HTTPException(status_code=400, detail=f"invalid advisory_id: {advisory_id!r}")
    return aid


class AdvisoryMeta(BaseModel):
    advisory_id: str
    title: Optional[str] = None
    url: Optional[str] = None
    published_date: Optional[str] = None
    advisory_type: Optional[str] = None
    document_type: Optional[str] = None
    s3_raw_path: Optional[str] = None


class AdvisoriesByCvesRequest(BaseModel):
    cve_ids: list[str] = Field(..., description="CVE IDs to intersect with advisory.cve_ids_mentioned.")


class AdvisoryWithMatches(AdvisoryMeta):
    cve_ids_mentioned: list[str] = []
    matched_cve_ids: list[str] = []


def _parse_array_column(val: Any) -> list[str]:
    """Snowflake ARRAY columns come back as a JSON string via the Python
    connector. Return a plain ``list[str]`` regardless of the raw form."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x) for x in val]
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return [str(x) for x in parsed]
    return []


@router.post(
    "/by-cves",
    response_model=list[AdvisoryWithMatches],
    summary="Advisories whose cve_ids_mentioned intersects the given CVE list",
    description=(
        "Returns the subset of the `advisories` table whose `cve_ids_mentioned` "
        "array contains at least one of the supplied CVE IDs. Intended for the "
        "weekly-brief UI — pass the CVEs the brief covers and get back the "
        "advisories worth linking. Result is ordered by published_date DESC."
    ),
)
def advisories_by_cves(body: AdvisoriesByCvesRequest) -> list[AdvisoryWithMatches]:
    # Uppercase + dedupe. CVE IDs are canonical-uppercase ('CVE-YYYY-NNNN');
    # we do UPPER on the Snowflake side too so casing drift in either source
    # doesn't silently drop matches.
    cve_ids = sorted({c.strip().upper() for c in body.cve_ids if c and c.strip()})
    if not cve_ids:
        return []

    placeholders = ",".join(["%s"] * len(cve_ids))
    # ARRAYS_OVERLAP would be tidier, but it needs both sides as ARRAY and the
    # snowflake-python-connector binds Python lists as VARIANT of string, not
    # ARRAY — LATERAL FLATTEN + IN sidesteps the cast entirely.
    query = f"""
        SELECT a.advisory_id, a.title, a.url, a.published_date,
               a.advisory_type, a.document_type, a.s3_raw_path,
               a.cve_ids_mentioned
        FROM advisories a
        WHERE EXISTS (
            SELECT 1
            FROM LATERAL FLATTEN(input => a.cve_ids_mentioned) f
            WHERE UPPER(f.value::string) IN ({placeholders})
        )
        ORDER BY a.published_date DESC NULLS LAST
    """
    rows = get_snowflake_service().execute_query(query, tuple(cve_ids))

    req_set = set(cve_ids)
    out: list[AdvisoryWithMatches] = []
    for r in rows:
        mentioned = _parse_array_column(r.get("cve_ids_mentioned"))
        matched = [c for c in mentioned if c.upper() in req_set]
        pub = r.get("published_date")
        out.append(
            AdvisoryWithMatches(
                advisory_id=r["advisory_id"],
                title=r.get("title"),
                url=r.get("url"),
                published_date=pub.isoformat() if pub is not None else None,
                advisory_type=r.get("advisory_type"),
                document_type=r.get("document_type"),
                s3_raw_path=r.get("s3_raw_path"),
                cve_ids_mentioned=mentioned,
                matched_cve_ids=matched,
            )
        )
    return out


@router.get(
    "/{advisory_id}/meta",
    response_model=AdvisoryMeta,
    summary="Advisory metadata (title, source URL, etc.)",
)
def advisory_meta(advisory_id: str = Path(...)) -> AdvisoryMeta:
    aid = _validate_advisory_id(advisory_id)
    sf = get_snowflake_service()
    row = sf.execute_one(
        """
        SELECT advisory_id, title, url, published_date,
               advisory_type, document_type, s3_raw_path
        FROM advisories
        WHERE LOWER(advisory_id) = %s
        LIMIT 1
        """,
        (aid,),
    )
    if not row:
        raise HTTPException(status_code=404, detail=f"advisory not found: {aid}")
    published = row.get("published_date")
    return AdvisoryMeta(
        advisory_id=row["advisory_id"],
        title=row.get("title"),
        url=row.get("url"),
        published_date=published.isoformat() if published is not None else None,
        advisory_type=row.get("advisory_type"),
        document_type=row.get("document_type"),
        s3_raw_path=row.get("s3_raw_path"),
    )


@router.get(
    "/{advisory_id}/html",
    response_class=HTMLResponse,
    summary="Raw advisory HTML from S3",
    description=(
        "Streams the advisory HTML that the ingestion pipeline uploaded to "
        "`s3://{bucket}/raw/advisories/{advisory_id}.html`. Returned as "
        "`text/html` so the caller can render it in an iframe."
    ),
)
def advisory_html(advisory_id: str = Path(...)) -> HTMLResponse:
    aid = _validate_advisory_id(advisory_id)

    # Prefer the s3_raw_path recorded by the ingest pipeline; fall back to the
    # canonical convention so this still works for advisories whose metadata
    # row is missing (e.g. partial re-ingests).
    sf = get_snowflake_service()
    row = sf.execute_one(
        "SELECT s3_raw_path FROM advisories WHERE LOWER(advisory_id) = %s LIMIT 1",
        (aid,),
    )
    key = (row or {}).get("s3_raw_path") or f"raw/advisories/{aid}.html"

    s3 = get_s3_storage()
    body = s3.download_document(key)
    if body is None:
        raise HTTPException(status_code=404, detail=f"advisory html not found: {key}")
    try:
        html = body.decode("utf-8")
    except UnicodeDecodeError:
        html = body.decode("utf-8", errors="replace")
    return HTMLResponse(content=html)
