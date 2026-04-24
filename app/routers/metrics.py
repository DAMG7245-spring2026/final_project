"""Operational metrics endpoints for the Streamlit Home dashboard."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.services.metrics import (
    freshness_by_source,
    overview_counts,
    recent_pipeline_runs,
    severity_distribution,
    top_kev_cves,
)

router = APIRouter(prefix="/metrics", tags=["CTI", "Metrics"])


@router.get("/overview", summary="Top-level platform counts")
async def get_overview() -> dict:
    try:
        return overview_counts()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"metrics overview failed: {exc}") from exc


@router.get("/severity-distribution", summary="CVSS severity distribution")
async def get_severity_distribution() -> dict:
    try:
        return {"items": severity_distribution()}
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"severity distribution failed: {exc}"
        ) from exc


@router.get("/top-kev", summary="Most recently added KEV CVEs")
async def get_top_kev(limit: int = Query(5, ge=1, le=25)) -> dict:
    try:
        return {"items": top_kev_cves(limit=limit), "limit": limit}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"top KEV query failed: {exc}") from exc


@router.get("/pipeline-runs", summary="Recent pipeline run statuses")
async def get_pipeline_runs(limit: int = Query(10, ge=1, le=50)) -> dict:
    try:
        return {"items": recent_pipeline_runs(limit=limit), "limit": limit}
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"pipeline runs query failed: {exc}"
        ) from exc


@router.get("/freshness", summary="Data freshness by source")
async def get_freshness() -> dict:
    try:
        return freshness_by_source()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"freshness query failed: {exc}") from exc
