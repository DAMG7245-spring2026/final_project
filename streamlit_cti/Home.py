"""CTI Home dashboard for operational overview."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pandas as pd
import streamlit as st
from lib.client import (
    get_metrics_freshness,
    get_metrics_overview,
    get_metrics_pipeline_runs,
    get_metrics_severity_distribution,
    get_metrics_top_kev,
    render_api_sidebar,
)
from streamlit_cti.theme import inject_global_theme

st.set_page_config(
    page_title="CTI Graph Console",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_global_theme()

render_api_sidebar()

base = str(st.session_state.cti_api_base).rstrip("/")

DASHBOARD_CSS = """
<style>
.home-hero {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: 1rem;
  margin-bottom: 1rem;
}
.home-hero h2 {
  margin: 0;
  font-size: 1.6rem;
}
.home-hero p {
  margin: 0.2rem 0 0 0;
  color: var(--muted);
  font-family: var(--mono);
}
.home-section-title {
  margin-top: 1rem;
  margin-bottom: 0.6rem;
  font-size: 0.85rem;
  font-family: var(--mono);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--muted);
}
.kpi-card {
  background: linear-gradient(180deg, var(--surface2) 0%, var(--surface) 100%);
  border: 1px solid var(--border2);
  border-radius: 12px;
  padding: 0.9rem 1rem;
}
.kpi-label {
  color: var(--muted);
  font-family: var(--mono);
  font-size: 0.72rem;
  letter-spacing: 0.07em;
  text-transform: uppercase;
}
.kpi-value {
  margin-top: 0.4rem;
  font-size: 1.7rem;
  font-weight: 700;
  color: var(--text);
}
.panel-shell {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 0.75rem 0.9rem 0.4rem 0.9rem;
}
.panel-title {
  margin: 0 0 0.6rem 0;
  font-size: 0.95rem;
  color: var(--text);
}
.fresh-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.45rem 0;
  border-bottom: 1px dashed var(--border2);
}
.fresh-row:last-child {
  border-bottom: 0;
}
.fresh-label {
  color: var(--muted);
}
.fresh-value {
  font-family: var(--mono);
  font-size: 0.84rem;
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 999px;
  padding: 0.15rem 0.5rem;
}
</style>
"""
st.markdown(DASHBOARD_CSS, unsafe_allow_html=True)


def _panel_error(panel_name: str, status: int, err: str) -> None:
    detail = err or "unknown error"
    st.warning(f"{panel_name} unavailable (`status={status}`): {detail}")


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _human_age(value: Any) -> str:
    dt = _parse_ts(value)
    if dt is None:
        return "n/a"
    delta = datetime.now(timezone.utc) - dt.astimezone(timezone.utc)
    hours = int(delta.total_seconds() // 3600)
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def _fmt_int(value: Any) -> str:
    return f"{int(value or 0):,}"


def _kpi_card(col: Any, label: str, value: Any) -> None:
    col.markdown(
        (
            '<div class="kpi-card">'
            f'<div class="kpi-label">{label}</div>'
            f'<div class="kpi-value">{_fmt_int(value)}</div>'
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def _freshness_line(label: str, value: Any) -> str:
    return (
        '<div class="fresh-row">'
        f'<span class="fresh-label">{label}</span>'
        f'<span class="fresh-value">{_human_age(value)}</span>'
        "</div>"
    )


st.markdown(
    """
<div class="home-hero">
  <div>
    <h2>CTI Platform Dashboard</h2>
    <p>Scene 1: live view of ingestion volume, active exploitation, and pipeline health.</p>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# -- Structured data brief --------------------------------------------------
st.markdown('<div class="home-section-title">Structured Data Sources</div>', unsafe_allow_html=True)
st.markdown(
    """
<style>
.src-card {
  background: linear-gradient(180deg, var(--surface2) 0%, var(--surface) 100%);
  border: 1px solid var(--border2);
  border-radius: 12px;
  padding: 0.9rem 1rem;
  height: 100%;
}
.src-card h4 {
  margin: 0 0 0.2rem 0;
  font-size: 1rem;
  color: var(--text);
}
.src-card .src-table {
  margin: 0.1rem 0 0.6rem 0;
  color: var(--muted);
  font-family: var(--mono);
  font-size: 0.72rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
.src-card ul {
  margin: 0;
  padding-left: 1rem;
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--text);
  line-height: 1.45;
}
.src-card ul li { margin: 0.05rem 0; }
.src-card .src-sub {
  margin-top: 0.55rem;
  font-family: var(--mono);
  font-size: 0.72rem;
  color: var(--muted);
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
</style>
""",
    unsafe_allow_html=True,
)

src_c1, src_c2, src_c3 = st.columns(3)
src_c1.markdown(
    """
<div class="src-card">
  <h4>CVE (NVD)</h4>
  <div class="src-table">cve_records · cve_cwe_mappings · cwe_records</div>
  <ul>
    <li>cve_id, published_date, last_modified, vuln_status</li>
    <li>description_en</li>
    <li>cvss_version, cvss_score, cvss_severity</li>
    <li>attack_vector, attack_complexity, privileges_required, user_interaction, scope</li>
    <li>confidentiality_impact, integrity_impact</li>
    <li>exploitability_score, impact_score</li>
    <li>cwe_ids, cpe_matches, has_exploit_ref, raw_json</li>
  </ul>
</div>
""",
    unsafe_allow_html=True,
)
src_c2.markdown(
    """
<div class="src-card">
  <h4>KEV (CISA)</h4>
  <div class="src-table">cve_records (is_kev = TRUE) · kev_pending_fetch</div>
  <ul>
    <li>is_kev</li>
    <li>kev_date_added, kev_due_date</li>
    <li>kev_vendor_project, kev_product</li>
    <li>kev_ransomware_use</li>
    <li>kev_required_action</li>
  </ul>
  <div class="src-sub">Queue: cve_id, kev_date_added, queued_at, fetched</div>
</div>
""",
    unsafe_allow_html=True,
)
src_c3.markdown(
    """
<div class="src-card">
  <h4>MITRE ATT&amp;CK</h4>
  <div class="src-table">attack_techniques · _tactics · _actors · _mitigations · _campaigns · _relationships</div>
  <ul>
    <li>techniques: mitre_id, stix_id, name, tactic, platforms, is_subtechnique, parent_id, mitre_version</li>
    <li>tactics: tactic_id, name, shortname, tactic_order</li>
    <li>actors: actor_name, external_id, aliases, country, motivation, target_sectors</li>
    <li>mitigations: mitigation_id, name, description</li>
    <li>campaigns: campaign_id, external_id, name, description</li>
    <li>relationships: source/target stix_id · name · type · relation_type</li>
  </ul>
</div>
""",
    unsafe_allow_html=True,
)

# -- Unstructured data brief ------------------------------------------------
st.markdown('<div class="home-section-title">Unstructured Data Sources — CISA Advisory Document Types</div>', unsafe_allow_html=True)

ud_r1c1, ud_r1c2, ud_r1c3 = st.columns(3)
ud_r1c1.markdown(
    """
<div class="src-card">
  <h4>MAR</h4>
  <div class="src-table">Malware Analysis Report · 1400t · h3/h4</div>
  <ul>
    <li>Executive / Malware Summary</li>
    <li>Findings (per-hash h4 sub-blocks)</li>
    <li>YARA / Sigma Rules</li>
    <li>Recommendations / Mitigations</li>
    <li>MITRE ATT&amp;CK Techniques</li>
    <li>Relationship Summary</li>
  </ul>
</div>
""",
    unsafe_allow_html=True,
)
ud_r1c2.markdown(
    """
<div class="src-card">
  <h4>ANALYSIS_REPORT</h4>
  <div class="src-table">Technical Analysis · 1200t · h2/h3</div>
  <ul>
    <li>Executive Summary / Introduction / Malware Summary</li>
    <li>Malware Metadata</li>
    <li>Malware Delivery</li>
    <li>Malware Functionality (Initiation / Persistence / C2)</li>
    <li>Detection (YARA / Sigma)</li>
    <li>Mitigations / Incident Response</li>
    <li>MITRE ATT&amp;CK Techniques</li>
    <li>Appendix</li>
  </ul>
</div>
""",
    unsafe_allow_html=True,
)
ud_r1c3.markdown(
    """
<div class="src-card">
  <h4>JOINT_CSA</h4>
  <div class="src-table">Multi-agency Advisory · 1000t · h2/h3</div>
  <ul>
    <li>Summary / Executive Summary</li>
    <li>Background / Threat Actor Activity</li>
    <li>Technical Details (ATT&amp;CK kill chain)</li>
    <li>Indicators of Compromise (IoC)</li>
    <li>MITRE ATT&amp;CK Techniques</li>
    <li>Detection / Mitigations / Incident Response</li>
    <li>Resources / References</li>
  </ul>
</div>
""",
    unsafe_allow_html=True,
)

ud_r2c1, ud_r2c2, ud_r2c3 = st.columns(3)
ud_r2c1.markdown(
    """
<div class="src-card">
  <h4>STOPRANSOMWARE</h4>
  <div class="src-table">#StopRansomware series · 1000t · h2/h3</div>
  <ul>
    <li>Summary / Executive Summary</li>
    <li>Background / Threat Actor Activity</li>
    <li>Technical Details</li>
    <li>Indicators of Compromise (IoC)</li>
    <li>MITRE ATT&amp;CK Techniques</li>
    <li>Detection / Mitigations / Incident Response</li>
    <li>Ransomware TTPs · Affiliates · Payment / Leak Sites</li>
    <li>Resources / References</li>
  </ul>
</div>
""",
    unsafe_allow_html=True,
)
ud_r2c2.markdown(
    """
<div class="src-card">
  <h4>IR_LESSONS</h4>
  <div class="src-table">Incident Response Lessons · 700t · h2/h3</div>
  <ul>
    <li>Summary</li>
    <li>Background / Engagement Overview</li>
    <li>Timeline / Key Events</li>
    <li>Key Findings / Noted Strengths</li>
    <li>Lessons Learned</li>
    <li>Mitigations / Recommendations</li>
    <li>MITRE ATT&amp;CK Techniques</li>
  </ul>
</div>
""",
    unsafe_allow_html=True,
)
ud_r2c3.markdown(
    """
<div class="src-card">
  <h4>CSA</h4>
  <div class="src-table">Single-agency Advisory · 1000t · auto/h3</div>
  <ul>
    <li>Summary</li>
    <li>Background</li>
    <li>Technical Details</li>
    <li>Indicators of Compromise (IoC)</li>
    <li>MITRE ATT&amp;CK Techniques</li>
    <li>Detection / Mitigations</li>
    <li>Resources / References</li>
  </ul>
</div>
""",
    unsafe_allow_html=True,
)

# -- Top: KPI cards ---------------------------------------------------------
st.markdown('<div class="home-section-title">Platform Health At A Glance</div>', unsafe_allow_html=True)
s_overview, d_overview, e_overview = get_metrics_overview(base)
if s_overview == 200 and isinstance(d_overview, dict):
    c1, c2, c3, c4 = st.columns(4)
    _kpi_card(c1, "Total CVEs ingested", d_overview.get("total_cves_ingested"))
    _kpi_card(c2, "KEV flagged", d_overview.get("kev_flagged"))
    _kpi_card(c3, "ATT&CK techniques loaded", d_overview.get("attack_techniques_loaded"))
    _kpi_card(c4, "Advisories indexed", d_overview.get("advisories_indexed"))
else:
    _panel_error("Overview metrics", s_overview, e_overview)

# -- Middle: severity + KEV list -------------------------------------------
st.markdown('<div class="home-section-title">Threat Landscape Summary</div>', unsafe_allow_html=True)
mid_l, mid_r = st.columns([1.2, 1.8])

with mid_l:
    st.markdown('<div class="panel-shell"><h4 class="panel-title">Severity Distribution</h4></div>', unsafe_allow_html=True)
    s_sev, d_sev, e_sev = get_metrics_severity_distribution(base)
    if s_sev == 200 and isinstance(d_sev, dict):
        items = d_sev.get("items") or []
        if items:
            sev_df = pd.DataFrame(items)
            sev_df["severity"] = sev_df["severity"].astype(str).str.upper()
            sev_df = sev_df.set_index("severity")
            st.bar_chart(sev_df["count"])
        else:
            st.info("No severity rows returned.")
    else:
        _panel_error("Severity distribution", s_sev, e_sev)

with mid_r:
    st.markdown('<div class="panel-shell"><h4 class="panel-title">Top 5 KEV CVEs This Week</h4></div>', unsafe_allow_html=True)
    s_kev, d_kev, e_kev = get_metrics_top_kev(base, limit=5)
    if s_kev == 200 and isinstance(d_kev, dict):
        rows = d_kev.get("items") or []
        if rows:
            kev_df = pd.DataFrame(rows)
            kev_df = kev_df.rename(
                columns={
                    "cve_id": "CVE ID",
                    "vendor": "Vendor",
                    "product": "Product",
                    "due_date": "Due Date",
                }
            )
            keep_cols = ["CVE ID", "Vendor", "Product", "Due Date"]
            st.dataframe(kev_df[keep_cols], use_container_width=True, hide_index=True)
        else:
            st.info("No KEV entries returned.")
    else:
        _panel_error("Top KEV list", s_kev, e_kev)

# -- Bottom: pipeline runs + freshness -------------------------------------
st.markdown('<div class="home-section-title">Pipeline Status</div>', unsafe_allow_html=True)
bot_l, bot_r = st.columns([2, 1])

with bot_l:
    st.markdown('<div class="panel-shell"><h4 class="panel-title">Recent Pipeline Runs</h4></div>', unsafe_allow_html=True)
    s_runs, d_runs, e_runs = get_metrics_pipeline_runs(base, limit=10)
    if s_runs == 200 and isinstance(d_runs, dict):
        runs = d_runs.get("items") or []
        if runs:
            run_df = pd.DataFrame(runs).rename(
                columns={
                    "dag": "DAG",
                    "source": "Source",
                    "status": "Status",
                    "rows_processed": "Rows Processed",
                    "duration_seconds": "Duration (s)",
                    "timestamp": "Timestamp",
                }
            )

            def _status_color(value: Any) -> str:
                v = str(value or "").lower()
                if v == "success":
                    return "background-color: rgba(46, 204, 138, 0.20);"
                if v in {"failed", "error"}:
                    return "background-color: rgba(248, 81, 73, 0.20);"
                return ""

            st.dataframe(
                run_df.style.map(_status_color, subset=["Status"]),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No pipeline run rows returned.")
    else:
        _panel_error("Pipeline runs", s_runs, e_runs)

with bot_r:
    st.markdown('<div class="panel-shell"><h4 class="panel-title">Data Freshness</h4>', unsafe_allow_html=True)
    s_fresh, d_fresh, e_fresh = get_metrics_freshness(base)
    if s_fresh == 200 and isinstance(d_fresh, dict):
        st.markdown(
            _freshness_line("NVD last updated", d_fresh.get("nvd"))
            + _freshness_line("KEV last synced", d_fresh.get("kev"))
            + _freshness_line("ATT&CK last reloaded", d_fresh.get("attck"))
            + _freshness_line("Neo4j last synced", d_fresh.get("neo4j"))
            + "</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown("</div>", unsafe_allow_html=True)
        _panel_error("Freshness indicators", s_fresh, e_fresh)
