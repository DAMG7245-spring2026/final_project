"""CISA KEV ingestion package."""

from ingestion.kev.client import KEV_FEED_URL, fetch_kev_catalog


def run_kev_sync(*args, **kwargs):
    """Lazy import to avoid hard dependency at package import time."""
    from ingestion.kev.enricher import run_kev_sync as _run_kev_sync

    return _run_kev_sync(*args, **kwargs)


__all__ = ["KEV_FEED_URL", "fetch_kev_catalog", "run_kev_sync"]
