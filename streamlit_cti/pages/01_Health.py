"""Visual health dashboard for GET /health."""

from __future__ import annotations

from datetime import datetime

import streamlit as st
from lib.client import health, render_api_sidebar

st.set_page_config(page_title="CTI — Health", layout="wide")

_DEP_ORDER = ("snowflake", "redis", "s3", "neo4j")


def _format_timestamp(raw: str | None) -> str:
    if not raw:
        return "—"
    try:
        # Handles ...Z and +00:00 from isoformat
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return raw


def _ordered_deps(deps: dict[str, str]) -> list[tuple[str, str]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for key in _DEP_ORDER:
        if key in deps:
            out.append((key, deps[key]))
            seen.add(key)
    for key in sorted(deps.keys()):
        if key not in seen:
            out.append((key, deps[key]))
    return out


def _unhealthy_detail(value: str) -> str | None:
    if value == "healthy":
        return None
    prefix = "unhealthy:"
    if value.lower().startswith(prefix):
        return value[len(prefix) :].strip()
    return value


def _render_health_payload(code: int, data: dict) -> None:
    overall = str(data.get("status") or "unknown")
    version = str(data.get("version") or "—")
    ts_raw = data.get("timestamp")
    ts_display = _format_timestamp(ts_raw if isinstance(ts_raw, str) else None)
    deps_raw = data.get("dependencies")
    deps: dict[str, str] = (
        {str(k): str(v) for k, v in deps_raw.items()}
        if isinstance(deps_raw, dict)
        else {}
    )

    all_ok = overall == "healthy" and all(v == "healthy" for v in deps.values()) if deps else overall == "healthy"

    if code == 200 and all_ok:
        st.success("**All systems operational** — every dependency reported healthy.")
    elif code in (200, 503):
        st.warning("**Degraded** — one or more dependencies are unhealthy. Review the table below.")
    else:
        st.info(f"**Response** — HTTP {code}, overall status: `{overall}`")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("HTTP", str(code))
    with c2:
        st.metric("App version", version)
    with c3:
        st.metric("Last check", ts_display)

    st.subheader("Dependencies")
    if not deps:
        st.caption("No dependency data in response.")
        return

    for name, value in _ordered_deps(deps):
        ok = value == "healthy"
        label = name.replace("_", " ").title()
        col_a, col_b = st.columns([1, 4])
        with col_a:
            if ok:
                st.markdown("### ✅")
            else:
                st.markdown("### ❌")
        with col_b:
            if ok:
                st.markdown(f"**{label}** — **OK**")
            else:
                st.markdown(f"**{label}** — **Down**")
                detail = _unhealthy_detail(value)
                if detail:
                    with st.expander("Error details", expanded=False):
                        st.code(detail, language=None)


base = render_api_sidebar()
st.header("GET /health")
if st.button("Fetch health", type="primary"):
    code, data, err = health(base)

    if code == 0:
        st.error(f"Could not reach the API: {err}")
    elif not isinstance(data, dict):
        st.error(err or "Unexpected response (not JSON object).")
        if data is not None:
            with st.expander("Raw response", expanded=False):
                st.write(data)
    else:
        if err and code not in (200, 503):
            st.error(err)
        elif err and code == 503:
            st.caption(f"Body note: {err[:500]}{'…' if len(err) > 500 else ''}")

        _render_health_payload(code, data)

        with st.expander("Raw JSON (debug)", expanded=False):
            st.json(data)
