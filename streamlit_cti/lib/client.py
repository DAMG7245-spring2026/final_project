"""HTTP client for the FastAPI CTI backend (httpx)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
import streamlit as st
from dotenv import load_dotenv


def repo_root() -> Path:
    """Project root (parent of ``streamlit_cti``)."""
    return Path(__file__).resolve().parent.parent.parent


def load_project_dotenv() -> None:
    load_dotenv(repo_root() / ".env", override=False)


def default_api_base() -> str:
    load_project_dotenv()
    return (os.environ.get("CTI_API_BASE") or "http://127.0.0.1:8000").rstrip("/")


def render_api_sidebar() -> str:
    """Sidebar URL field; returns normalized base URL."""
    if "cti_api_base" not in st.session_state:
        st.session_state.cti_api_base = default_api_base()
    st.sidebar.text_input(
        "API base URL",
        key="cti_api_base",
        help="FastAPI root, e.g. http://127.0.0.1:8000. Override with CTI_API_BASE in .env.",
    )
    return str(st.session_state.cti_api_base).rstrip("/")


def get_client(base: str) -> httpx.Client:
    return httpx.Client(base_url=base, timeout=120.0)


def request_json(
    method: str,
    path: str,
    *,
    base: str,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> tuple[int, Any | None, str]:
    """
    Returns (status_code, parsed_json_or_none, error_message).
    For non-JSON bodies, error_message may hold a snippet of text.
    """
    try:
        with get_client(base) as client:
            r = client.request(method, path, params=params, json=json_body)
    except httpx.RequestError as e:
        return 0, None, str(e)
    try:
        data = r.json() if r.content else None
    except Exception:
        data = None
    err = "" if r.is_success else (r.text[:2000] if r.text else r.reason_phrase)
    return r.status_code, data, err


def health(base: str) -> tuple[int, Any | None, str]:
    return request_json("GET", "/health", base=base)


def get_cve(base: str, cve_id: str) -> tuple[int, Any | None, str]:
    return request_json("GET", f"/cve/{cve_id}", base=base)


def get_actor(base: str, actor_id: str) -> tuple[int, Any | None, str]:
    from urllib.parse import quote

    return request_json("GET", f"/actor/{quote(actor_id, safe='')}", base=base)


def get_technique(base: str, technique_id: str) -> tuple[int, Any | None, str]:
    return request_json("GET", f"/technique/{technique_id.strip().upper()}", base=base)


def get_attack_path(
    base: str,
    *,
    from_cve: str | None = None,
    from_actor: str | None = None,
    from_technique: str | None = None,
    max_hops: int = 3,
    limit: int = 10,
) -> tuple[int, Any | None, str]:
    params: dict[str, Any] = {"max_hops": max_hops, "limit": limit}
    if from_cve:
        params["from_cve"] = from_cve
    if from_actor:
        params["from_actor"] = from_actor
    if from_technique:
        params["from_technique"] = from_technique
    return request_json("GET", "/graph/attack-path", base=base, params=params)


def post_hybrid_search(base: str, body: dict[str, Any]) -> tuple[int, Any | None, str]:
    return request_json(
        "POST", "/search/advisory-chunks/hybrid", base=base, json_body=body
    )


def post_vector_search(base: str, body: dict[str, Any]) -> tuple[int, Any | None, str]:
    return request_json("POST", "/search/advisory-chunks", base=base, json_body=body)


def post_query(base: str, query: str) -> tuple[int, Any | None, str]:
    return request_json("POST", "/query", base=base, json_body={"query": query})


def get_weekly_brief(base: str) -> tuple[int, Any | None, str]:
    return request_json("GET", "/brief/weekly", base=base)
