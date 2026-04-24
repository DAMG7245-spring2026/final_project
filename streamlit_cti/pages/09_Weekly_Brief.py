"""Weekly CVE threat-intel brief — SSE streaming UI.

Reads `GET /weekly-brief/stream` from the backend and renders:
  * top: markdown summary streamed token-by-token (event: markdown)
  * bottom: expandable cards for top_cves + newly_added_kev (event: cves)
"""

from __future__ import annotations

import json
import os
import re
from datetime import date, timedelta

import html as html_lib

import requests
import streamlit as st
import streamlit.components.v1 as components

# Matches CISA advisory IDs wrapped in backticks as emitted by the synthesis
# prompt (e.g. `aa23-131a`, `ar25-012`). We only linkify the backticked form
# so we never accidentally rewrite free-standing IDs inside existing markdown
# links or code blocks.
_ADVISORY_ID_BACKTICK_RE = re.compile(r"`([a-z]{2}\d{2}-\d{3}[a-z]?)`", re.IGNORECASE)

st.set_page_config(page_title="CTI — Weekly Brief", layout="wide")

API_BASE = os.getenv("CTI_API_BASE", "http://localhost:8000")

st.header("Weekly CVE Threat-Intel Brief")
st.caption(f"Backend: `{API_BASE}/weekly-brief/stream`")

st.markdown(
    """
| Tier | Condition | Meaning |
|---|---|---|
| 1 | `is_kev = TRUE` AND `kev_ransomware_use = 'Known'` | Actively used by ransomware |
| 2 | `is_kev = TRUE` AND `kev_date_added` within window | Newly added to KEV this week |
| 3 | `has_exploit_ref = TRUE` AND `cvss_score >= 9.0` | Critical CVE with public exploit |
| 4 | `cvss_severity = 'CRITICAL'` AND `confidentiality_impact = 'HIGH'` | Worst-case severity |
| 5 | Everything else (excluded by default via `max_tier=4`) | Long-tail noise |
"""
)

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
        # Only show the Evidence paragraph when the graph retriever actually
        # returned rows — otherwise the paragraph is just advisory-chunk
        # noise, which we already strip below.
        if ev and (ev.get("graph_row_count") or 0) > 0 and ev.get("rag_answer"):
            # Drop the "## Advisory passages" section — raw chunk text is
            # noisy and the referenced advisories are already available as
            # expandable HTML at the bottom of the page.
            paragraph = ev["rag_answer"].split("## Advisory passages", 1)[0].rstrip()
            if paragraph:
                st.markdown("---")
                with st.expander("Evidence paragraph", expanded=False):
                    st.markdown(paragraph)


# ---- session state --------------------------------------------------------

for key, default in [
    ("meta", None),
    ("cves_data", None),
    ("markdown_final", ""),
    ("done_info", None),
    ("error", None),
    ("advisory_url_by_id", {}),
]:
    if key not in st.session_state:
        st.session_state[key] = default


@st.cache_data(show_spinner=False)
def _fetch_advisory_html(advisory_id: str) -> str | None:
    try:
        r = requests.get(f"{API_BASE}/advisory/{advisory_id}/html", timeout=30)
        if r.status_code == 200:
            return r.text
    except requests.RequestException:
        pass
    return None


@st.cache_data(show_spinner=False)
def _fetch_advisories_by_cves(cve_ids: tuple[str, ...]) -> list[dict]:
    """Ask the backend which advisories mention any of these CVEs.

    Hits ``POST /advisory/by-cves`` which joins against the Snowflake
    ``advisories.cve_ids_mentioned`` column. Cached by the tuple of CVE IDs.
    """
    if not cve_ids:
        return []
    try:
        r = requests.post(
            f"{API_BASE}/advisory/by-cves",
            json={"cve_ids": list(cve_ids)},
            timeout=30,
        )
        if r.status_code == 200:
            return r.json()
    except requests.RequestException:
        pass
    return []


def _build_advisory_url_lookup(advisories: list[dict]) -> dict[str, str]:
    """Lowercased advisory_id → link URL. Prefer the CISA source URL; fall
    back to our own ``/advisory/{id}/html`` endpoint so unresolvable IDs
    still have somewhere to click through to."""
    lookup: dict[str, str] = {}
    for a in advisories:
        aid = a.get("advisory_id")
        if not aid:
            continue
        url = a.get("url") or f"{API_BASE}/advisory/{aid}/html"
        lookup[aid.lower()] = url
    return lookup


def _linkify_advisory_ids(md: str, url_by_aid: dict[str, str]) -> str:
    """Replace `` `aa23-131a` `` with ``[`aa23-131a`](url)`` when we have a
    URL for that advisory. Case preserved in the visible text."""
    if not md or not url_by_aid:
        return md

    def repl(m: "re.Match[str]") -> str:
        aid_literal = m.group(1)
        url = url_by_aid.get(aid_literal.lower())
        if not url:
            return m.group(0)
        return f"[`{aid_literal}`]({url})"

    return _ADVISORY_ID_BACKTICK_RE.sub(repl, md)


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
                    # Pre-fetch the advisory URL lookup now — the `cves` event
                    # carries every CVE ID we need, and having the map ready
                    # lets us linkify the markdown in a single pass after the
                    # stream finishes.
                    cd = st.session_state.cves_data or {}
                    cve_id_set: dict[str, None] = {}
                    for c in (cd.get("top_cves") or []) + (cd.get("newly_added_kev") or []):
                        cid = c.get("cve_id")
                        if cid:
                            cve_id_set.setdefault(cid, None)
                    advisories = _fetch_advisories_by_cves(tuple(cve_id_set.keys()))
                    st.session_state.advisory_url_by_id = _build_advisory_url_lookup(advisories)
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
            # Final render with advisory IDs linkified — during streaming we
            # render raw to avoid re-running the regex on every token.
            md_ph.markdown(
                _linkify_advisory_ids(
                    st.session_state.markdown_final,
                    st.session_state.advisory_url_by_id,
                )
            )

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
        st.markdown(
            _linkify_advisory_ids(
                st.session_state.markdown_final,
                st.session_state.advisory_url_by_id,
            )
        )

# ---- referenced advisories (bottom) --------------------------------------


def _render_advisories_section(cves_data: dict) -> None:
    # Collect every CVE the brief surfaced (top + newly added), dedup in-order.
    seen: dict[str, None] = {}
    for c in (cves_data.get("top_cves") or []) + (cves_data.get("newly_added_kev") or []):
        cid = c.get("cve_id")
        if cid:
            seen.setdefault(cid, None)
    cve_ids = list(seen.keys())
    if not cve_ids:
        return

    advisories = _fetch_advisories_by_cves(tuple(cve_ids))
    if not advisories:
        st.markdown("---")
        st.caption(
            "No advisories in the Snowflake `advisories` table mention the "
            "CVEs covered by this brief."
        )
        return

    st.markdown("---")
    st.header(f"Referenced Advisories ({len(advisories)})")
    st.caption(
        "Filtered from the Snowflake `advisories` table — only advisories "
        "whose `cve_ids_mentioned` column contains at least one CVE from this "
        "brief. HTML served from S3 via `/advisory/{id}/html`."
    )

    for a in advisories:
        aid = a.get("advisory_id")
        matched = a.get("matched_cve_ids") or []
        match_str = ", ".join(matched) if matched else "—"
        label = f"{aid}  ·  mentions: {match_str}"
        with st.expander(label, expanded=False):
            title = a.get("title") or "—"
            url = a.get("url")
            pub = a.get("published_date") or "—"
            doc_type = a.get("document_type") or a.get("advisory_type") or "—"
            st.markdown(f"**{title}**")
            st.caption(f"published: {pub} · type: {doc_type}")
            if url:
                st.markdown(f"[Source on CISA]({url})")

            if st.button("Load HTML", key=f"load_advisory_{aid}"):
                st.session_state[f"advisory_open_{aid}"] = True

            if st.session_state.get(f"advisory_open_{aid}"):
                html_src = _fetch_advisory_html(aid)
                if html_src is None:
                    st.warning(f"Could not fetch HTML for `{aid}`.")
                else:
                    # Sandbox the advisory HTML — no scripts, no top-nav, no
                    # same-origin access to the Streamlit page.
                    escaped = html_lib.escape(html_src, quote=True)
                    iframe = (
                        f'<iframe sandbox="" srcdoc="{escaped}" '
                        f'style="width:100%;height:700px;border:1px solid #ddd;'
                        f'border-radius:6px;"></iframe>'
                    )
                    components.html(iframe, height=720, scrolling=False)


# ---- CVE detail list (bottom) --------------------------------------------

cves_data = st.session_state.cves_data
if cves_data:
    _render_advisories_section(cves_data)

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
