"""Weekly CVE threat-intel brief — SSE streaming UI.

Reads `GET /weekly-brief/stream` from the backend and renders:
  * top: markdown summary streamed token-by-token (event: markdown)
  * bottom: expandable cards for top_cves + newly_added_kev (event: cves)
"""

from __future__ import annotations

import json
import os
from datetime import date, timedelta

import requests
import streamlit as st

st.set_page_config(page_title="CTI — Weekly Brief", layout="wide")

API_BASE = os.getenv("CTI_API_BASE", "http://localhost:8000")

st.header("Weekly CVE Threat-Intel Brief")
st.caption(f"Backend: `{API_BASE}/weekly-brief/stream`")

with st.sidebar:
    st.subheader("Window")
    default_end = date.today()
    default_start = default_end - timedelta(days=7)
    window_start = st.date_input("window_start", value=default_start)
    window_end = st.date_input("window_end", value=default_end)
    limit = st.number_input("top-N limit", min_value=1, max_value=50, value=10)
    max_tier = st.number_input("max_tier", min_value=1, max_value=5, value=4)
    newly_added_limit = st.number_input(
        "newly_added_limit", min_value=1, max_value=50, value=5
    )


def _sse_events(resp: requests.Response):
    """Minimal SSE parser: yields (event_name, data_str) for each frame."""
    event_name = "message"
    data_lines: list[str] = []
    for raw in resp.iter_lines(decode_unicode=True):
        if raw is None:
            continue
        if raw == "":
            if data_lines:
                yield event_name, "\n".join(data_lines)
            event_name = "message"
            data_lines = []
            continue
        if raw.startswith(":"):
            continue  # comment / keepalive
        if raw.startswith("event:"):
            event_name = raw[len("event:") :].strip()
        elif raw.startswith("data:"):
            data_lines.append(raw[len("data:") :].lstrip())
    if data_lines:
        yield event_name, "\n".join(data_lines)


def _severity_badge(severity: str | None) -> str:
    colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }
    return colors.get((severity or "").upper(), "⚪")


def _render_cve_expander(cve: dict, evidence_by_id: dict[str, dict]) -> None:
    cve_id = cve.get("cve_id", "?")
    score = cve.get("cvss_score")
    sev = cve.get("cvss_severity") or "—"
    badge = _severity_badge(sev)
    tier = cve.get("tier")
    tier_reason = cve.get("tier_reason") or ""
    vendor = cve.get("kev_vendor_project") or "—"
    product = cve.get("kev_product") or "—"
    header = (
        f"{badge} **{cve_id}** — CVSS {score} ({sev}) · Tier {tier} · "
        f"{vendor} / {product}"
    )
    with st.expander(header, expanded=False):
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("CVSS", f"{score}")
            st.caption(f"Severity: {sev}")
        with c2:
            st.metric("Tier", f"{tier}")
            st.caption(tier_reason)
        with c3:
            st.metric("KEV", "Yes" if cve.get("is_kev") else "No")
            st.caption(f"Ransomware use: {cve.get('kev_ransomware_use') or '—'}")

        st.markdown("**Description**")
        st.write(cve.get("description_en") or "_(no description)_")

        meta_cols = st.columns(2)
        with meta_cols[0]:
            st.markdown("**NVD metadata**")
            st.write(
                {
                    "published_date": cve.get("published_date"),
                    "last_modified": cve.get("last_modified"),
                    "vuln_status": cve.get("vuln_status"),
                    "exploitability_score": cve.get("exploitability_score"),
                    "impact_score": cve.get("impact_score"),
                    "confidentiality_impact": cve.get("confidentiality_impact"),
                    "integrity_impact": cve.get("integrity_impact"),
                    "has_exploit_ref": cve.get("has_exploit_ref"),
                }
            )
        with meta_cols[1]:
            st.markdown("**KEV metadata**")
            st.write(
                {
                    "kev_date_added": cve.get("kev_date_added"),
                    "kev_due_date": cve.get("kev_due_date"),
                    "kev_required_action": cve.get("kev_required_action"),
                    "kev_vendor_project": cve.get("kev_vendor_project"),
                    "kev_product": cve.get("kev_product"),
                }
            )

        ev = evidence_by_id.get(cve_id)
        if ev:
            st.markdown("---")
            st.markdown("**RAG evidence**")
            st.caption(
                f"route={ev.get('route')} · graph_rows={ev.get('graph_row_count', 0)} · "
                f"chunks={ev.get('chunk_count', 0)}"
            )
            if ev.get("rag_answer"):
                with st.expander("Evidence paragraph", expanded=False):
                    st.markdown(ev["rag_answer"])
            if ev.get("graph_cypher"):
                with st.expander("Generated Cypher", expanded=False):
                    st.code(ev["graph_cypher"], language="cypher")


# ---- session state --------------------------------------------------------

for key, default in [
    ("meta", None),
    ("cves_data", None),
    ("markdown_final", ""),
    ("done_info", None),
    ("error", None),
]:
    if key not in st.session_state:
        st.session_state[key] = default


run = st.button("Fetch brief (stream)", type="primary")

if run:
    # reset state for a new run
    st.session_state.meta = None
    st.session_state.cves_data = None
    st.session_state.markdown_final = ""
    st.session_state.done_info = None
    st.session_state.error = None

    params = {
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "limit": int(limit),
        "max_tier": int(max_tier),
        "newly_added_limit": int(newly_added_limit),
    }

    status_ph = st.empty()
    meta_ph = st.empty()
    st.subheader("Weekly brief")
    md_ph = st.empty()

    try:
        status_ph.info("Fetching digest + RAG evidence…")
        with requests.get(
            f"{API_BASE}/weekly-brief/stream",
            params=params,
            stream=True,
            timeout=600,
            headers={"Accept": "text/event-stream"},
        ) as resp:
            resp.raise_for_status()

            buffer: list[str] = []
            for event_name, data in _sse_events(resp):
                if event_name == "meta":
                    try:
                        st.session_state.meta = json.loads(data)
                    except json.JSONDecodeError:
                        st.session_state.meta = {"raw": data}
                    meta = st.session_state.meta
                    with meta_ph.container():
                        c = st.columns(6)
                        c[0].metric("total_modified", meta.get("total_modified", "—"))
                        c[1].metric("newly_published", meta.get("newly_published", "—"))
                        c[2].metric("critical", meta.get("critical_count", "—"))
                        c[3].metric("kev_added", meta.get("kev_added_count", "—"))
                        c[4].metric("kev_ransomware", meta.get("kev_ransomware_count", "—"))
                        c[5].metric("has_exploit_ref", meta.get("has_exploit_ref_count", "—"))
                    status_ph.info("Digest ready — fanning out RAG workers…")

                elif event_name == "cves":
                    try:
                        st.session_state.cves_data = json.loads(data)
                    except json.JSONDecodeError:
                        st.session_state.cves_data = None
                    status_ph.info("RAG evidence ready — streaming markdown…")

                elif event_name == "markdown":
                    try:
                        payload = json.loads(data)
                        delta = payload.get("delta", "")
                    except json.JSONDecodeError:
                        delta = ""
                    if delta:
                        buffer.append(delta)
                        md_ph.markdown("".join(buffer))

                elif event_name == "done":
                    try:
                        st.session_state.done_info = json.loads(data)
                    except json.JSONDecodeError:
                        st.session_state.done_info = {"raw": data}
                    status_ph.success(
                        f"Done — workers={st.session_state.done_info.get('worker_count', '?')}, "
                        f"markdown_chars={st.session_state.done_info.get('markdown_chars', '?')}"
                    )

                elif event_name == "error":
                    try:
                        err = json.loads(data).get("detail", data)
                    except json.JSONDecodeError:
                        err = data
                    st.session_state.error = err
                    status_ph.error(f"Server error: {err}")
                    break

            st.session_state.markdown_final = "".join(buffer)

    except requests.exceptions.ConnectionError:
        st.session_state.error = f"Cannot connect to backend at {API_BASE}"
        st.error(st.session_state.error)
    except requests.exceptions.HTTPError as e:
        st.session_state.error = f"HTTP error: {e}"
        st.error(st.session_state.error)
    except Exception as e:  # pylint: disable=broad-except
        st.session_state.error = str(e)
        st.error(st.session_state.error)

else:
    # Re-render whatever's in session state (e.g. after a widget interaction)
    if st.session_state.meta:
        meta = st.session_state.meta
        c = st.columns(6)
        c[0].metric("total_modified", meta.get("total_modified", "—"))
        c[1].metric("newly_published", meta.get("newly_published", "—"))
        c[2].metric("critical", meta.get("critical_count", "—"))
        c[3].metric("kev_added", meta.get("kev_added_count", "—"))
        c[4].metric("kev_ransomware", meta.get("kev_ransomware_count", "—"))
        c[5].metric("has_exploit_ref", meta.get("has_exploit_ref_count", "—"))
    if st.session_state.markdown_final:
        st.subheader("Weekly brief")
        st.markdown(st.session_state.markdown_final)

# ---- CVE detail list (bottom) --------------------------------------------

cves_data = st.session_state.cves_data
if cves_data:
    st.markdown("---")
    st.header("Retrieved CVEs")

    evidence_list = cves_data.get("evidence") or []
    evidence_by_id = {}
    for ev in evidence_list:
        cve_obj = ev.get("cve") or {}
        cve_id = cve_obj.get("cve_id")
        if cve_id:
            evidence_by_id[cve_id] = ev

    top_cves = cves_data.get("top_cves") or []
    newly = cves_data.get("newly_added_kev") or []

    tabs = st.tabs(
        [f"Top CVEs ({len(top_cves)})", f"Newly added KEV ({len(newly)})"]
    )
    with tabs[0]:
        if not top_cves:
            st.caption("No top CVEs for this window.")
        for cve in top_cves:
            _render_cve_expander(cve, evidence_by_id)
    with tabs[1]:
        if not newly:
            st.caption("No newly added KEV this week.")
        for cve in newly:
            _render_cve_expander(cve, evidence_by_id)
