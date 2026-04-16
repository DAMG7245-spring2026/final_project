"""Fetch CISA KEV catalog feed."""

from __future__ import annotations

from typing import Any

import httpx

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_catalog(url: str = KEV_FEED_URL, timeout_sec: float = 60.0) -> list[dict[str, Any]]:
    """Fetch KEV feed JSON and return vulnerability entries."""
    with httpx.Client(timeout=timeout_sec) as client:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        return []
    return [v for v in vulns if isinstance(v, dict)]
