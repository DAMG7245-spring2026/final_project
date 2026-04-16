"""NVD CVE API 2.0 client (rate-limited httpx)."""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path
from typing import Any

import httpx

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
# NVD: 5 requests / 30s without API key; 50 / 30s with key (~0.6s min spacing).
PACE_NO_API_KEY_SEC = 6.0
PACE_WITH_API_KEY_SEC = 0.65


def resolve_nvd_request_interval(
    api_key: str | None,
    *,
    explicit_override: float | None = None,
) -> float:
    """
    Seconds to sleep between paginated delta requests.
    explicit_override wins; then Settings.nvd_min_request_interval_sec;
    then key-based default.
    """
    if explicit_override is not None:
        return float(explicit_override)
    from app.config import get_settings

    o = get_settings().nvd_min_request_interval_sec
    if o is not None:
        return float(o)
    if api_key and str(api_key).strip():
        return PACE_WITH_API_KEY_SEC
    return PACE_NO_API_KEY_SEC


def _headers(api_key: str | None) -> dict[str, str]:
    h: dict[str, str] = {}
    if api_key:
        h["apiKey"] = api_key
    return h


def _paginate_delta(
    start_date: date,
    end_date: date,
    api_key: str | None,
    client: httpx.Client,
    *,
    explicit_interval: float | None = None,
) -> Any:
    """Yield (page_vulnerabilities_list, page_index_starting_at_0)."""
    start_index = 0
    page_no = 0
    interval = resolve_nvd_request_interval(api_key, explicit_override=explicit_interval)
    headers = _headers(api_key)
    while True:
        if start_index > 0:
            time.sleep(interval)
        params: dict[str, str | int] = {
            "lastModStartDate": f"{start_date.isoformat()}T00:00:00.000",
            "lastModEndDate": f"{end_date.isoformat()}T23:59:59.999",
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }
        r = client.get(NVD_BASE_URL, params=params, headers=headers)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        total = int(data.get("totalResults", 0))
        yield vulns, page_no
        page_no += 1
        start_index += RESULTS_PER_PAGE
        if start_index >= total or not vulns:
            break


def fetch_nvd_delta(
    start_date: date,
    end_date: date,
    api_key: str | None = None,
    *,
    client: httpx.Client | None = None,
    explicit_interval: float | None = None,
) -> list[dict[str, Any]]:
    """
    Fetch CVEs whose lastModifiedDate falls in [start_date, end_date] (inclusive days).
    Returns raw `vulnerabilities[]` items (each contains a `cve` object).
    """
    own_client = client is None
    if client is None:
        client = httpx.Client(timeout=120.0, follow_redirects=True)

    all_vulns: list[dict[str, Any]] = []
    try:
        for vulns, _ in _paginate_delta(
            start_date,
            end_date,
            api_key,
            client,
            explicit_interval=explicit_interval,
        ):
            all_vulns.extend(vulns)
        return all_vulns
    finally:
        if own_client:
            client.close()


def fetch_nvd_delta_to_ndjson(
    start_date: date,
    end_date: date,
    out_path: str | Path,
    api_key: str | None = None,
    *,
    client: httpx.Client | None = None,
    explicit_interval: float | None = None,
) -> dict[str, int]:
    """
    Stream paginated NVD results to a UTF-8 NDJSON file (one vulnerability JSON per line).
    Returns {"written": n, "pages": n}.
    """
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    own_client = client is None
    if client is None:
        client = httpx.Client(timeout=120.0, follow_redirects=True)

    written = 0
    pages = 0
    try:
        with path.open("w", encoding="utf-8") as f:
            for vulns, _ in _paginate_delta(
                start_date,
                end_date,
                api_key,
                client,
                explicit_interval=explicit_interval,
            ):
                pages += 1
                for item in vulns:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")
                    written += 1
        return {"written": written, "pages": pages}
    finally:
        if own_client:
            client.close()


def fetch_single_cve(
    cve_id: str,
    api_key: str | None = None,
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any] | None:
    """Fetch one CVE by ID; return the raw vulnerability dict or None."""
    own_client = client is None
    if client is None:
        client = httpx.Client(timeout=120.0, follow_redirects=True)
    headers = _headers(api_key)
    try:
        r = client.get(
            NVD_BASE_URL,
            params={"cveId": cve_id},
            headers=headers,
        )
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        return vulns[0] if vulns else None
    finally:
        if own_client:
            client.close()


def fetch_single_cve_to_ndjson(
    cve_id: str,
    out_path: str | Path,
    api_key: str | None = None,
    *,
    client: httpx.Client | None = None,
) -> dict[str, int]:
    """Fetch one CVE and append as a single NDJSON line (or empty file if not found)."""
    item = fetch_single_cve(cve_id, api_key, client=client)
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not item:
        path.write_text("", encoding="utf-8")
        return {"written": 0, "pages": 1}
    path.write_text(json.dumps(item, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"written": 1, "pages": 1}
