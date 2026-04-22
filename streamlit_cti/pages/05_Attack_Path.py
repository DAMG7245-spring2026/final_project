"""Attack Path Explorer — visualizes GET /graph/attack-path (no backend changes)."""

from __future__ import annotations

import html
import json
from typing import Any

import streamlit as st
import streamlit.components.v1 as components
from lib.client import get_attack_path, render_api_sidebar
from pyvis.network import Network

_LABEL_PRIORITY = ("CVE", "CWE", "Technique", "Actor")
_PILL_COLORS = {
    "CVE": "#E24B4A",
    "CWE": "#378ADD",
    "Technique": "#7F77DD",
    "Actor": "#BA7517",
}
_DEFAULT_NODE = "#888780"

AP_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
section[data-testid="stMain"] .block-container,
.stMain .block-container {
  font-family: 'IBM Plex Sans', sans-serif !important;
  background: #0d1117 !important;
  color: #e6edf3 !important;
  padding-top: 1.25rem !important;
  max-width: 1200px !important;
}
section[data-testid="stMain"] h1,
.stMain h1 { font-size: 22px !important; font-weight: 600 !important; letter-spacing: -0.02em !important; color: #e6edf3 !important; border: none !important; }
section[data-testid="stMain"] [data-testid="stCaptionContainer"] p,
.stMain [data-testid="stCaptionContainer"] p { color: #8b949e !important; font-size: 13px !important; }
section[data-testid="stMain"] label, .stMain label { color: #8b949e !important; font-size: 11px !important; font-weight: 500 !important; text-transform: uppercase !important; letter-spacing: 0.04em !important; }
section[data-testid="stMain"] [data-baseweb="input"] input,
.stMain [data-baseweb="input"] input {
  background: #21262d !important; border-color: #30363d !important; color: #e6edf3 !important;
  font-family: 'JetBrains Mono', monospace !important; border-radius: 7px !important;
}
section[data-testid="stMain"] button[kind="primary"],
.stMain button[kind="primary"] {
  background-color: #58a6ff !important; color: #fff !important; border: none !important;
  border-radius: 7px !important; font-weight: 500 !important;
}
section[data-testid="stMain"] button[kind="primary"]:hover,
.stMain button[kind="primary"]:hover { background-color: #79b8ff !important; }
section[data-testid="stMain"] button[kind="secondary"],
.stMain button[kind="secondary"] {
  background: transparent !important; color: #8b949e !important; border: 1px solid #30363d !important;
}
section[data-testid="stMain"] [data-testid="stVerticalBlockBorderWrapper"],
.stMain [data-testid="stVerticalBlockBorderWrapper"] {
  background: #161b22 !important; border: 1px solid #30363d !important; border-radius: 10px !important;
}
.ap-metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 16px 0 18px 0; }
.ap-metric { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 16px; }
.ap-metric-label { font-size: 11px; font-weight: 500; color: #8b949e; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px; }
.ap-metric-val { font-size: 26px; font-weight: 600; font-family: 'JetBrains Mono', monospace; color: #e6edf3; }
.ap-metric-val-red { color: #f85149 !important; }
.ap-path-card {
  background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 14px 16px; margin-bottom: 10px;
}
.ap-path-card.ap-selected { border-color: #58a6ff !important; background: rgba(88, 166, 255, 0.05) !important; }
.ap-path-meta { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }
.ap-path-num { font-size: 12px; font-weight: 500; color: #8b949e; font-family: 'JetBrains Mono', monospace; }
.ap-badge-row { display: flex; gap: 4px; flex-wrap: wrap; }
.ap-node-chain { display: flex; align-items: center; flex-wrap: wrap; gap: 4px; }
.ap-pill { display: inline-flex; align-items: center; gap: 5px; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 500; font-family: 'JetBrains Mono', monospace; }
.ap-pill-type { font-size: 9px; opacity: 0.75; text-transform: uppercase; letter-spacing: 0.05em; }
.ap-pill-cve { background: rgba(248, 81, 73, 0.15); color: #ff8b82; border: 1px solid rgba(248, 81, 73, 0.25); }
.ap-pill-cwe { background: rgba(88, 166, 255, 0.15); color: #79b8ff; border: 1px solid rgba(88, 166, 255, 0.25); }
.ap-pill-tech { background: rgba(188, 140, 255, 0.15); color: #d2a8ff; border: 1px solid rgba(188, 140, 255, 0.25); }
.ap-pill-actor { background: rgba(210, 153, 34, 0.15); color: #e3b341; border: 1px solid rgba(210, 153, 34, 0.25); }
.ap-pill-default { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
.ap-rel-arrow { color: #484f58; font-size: 11px; font-family: 'JetBrains Mono', monospace; }
.ap-badge-kev { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 5px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; background: #3d1b1b; color: #f85149; border: 1px solid rgba(248, 81, 73, 0.3); }
.ap-badge-critical { background: #3d1b1b; color: #f85149; padding: 2px 8px; border-radius: 5px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; }
.ap-badge-high { background: #2d2008; color: #d29922; padding: 2px 8px; border-radius: 5px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; }
.ap-badge-medium { background: #1b2d4f; color: #58a6ff; padding: 2px 8px; border-radius: 5px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; }
.ap-badge-low { background: #21262d; color: #8b949e; padding: 2px 8px; border-radius: 5px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; }
.ap-detail-panel { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 16px; }
.ap-detail-title { font-size: 12px; font-weight: 600; color: #8b949e; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 14px; }
.ap-score-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 14px; }
.ap-score-card { background: #21262d; border-radius: 6px; padding: 10px 12px; }
.ap-score-label { font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 3px; }
.ap-score-val { font-size: 20px; font-weight: 600; font-family: 'JetBrains Mono', monospace; color: #e6edf3; }
.ap-score-val-crit { color: #f85149 !important; }
.ap-prop-row { display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-bottom: 1px solid rgba(48, 54, 61, 0.5); font-size: 12px; }
.ap-prop-row:last-child { border-bottom: none; }
.ap-prop-key { color: #8b949e; }
.ap-prop-val { color: #e6edf3; font-family: 'JetBrains Mono', monospace; font-size: 11px; text-align: right; max-width: 55%; word-break: break-all; }
.ap-kev-section { background: rgba(248, 81, 73, 0.06); border: 1px solid rgba(248, 81, 73, 0.2); border-radius: 8px; padding: 12px; margin-top: 12px; }
.ap-kev-title { font-size: 11px; font-weight: 600; color: #f85149; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 8px; }
.ap-required-action { background: rgba(248, 81, 73, 0.1); border-left: 3px solid #f85149; border-radius: 0 6px 6px 0; padding: 8px 10px; font-size: 11px; color: #ffa7a3; line-height: 1.5; margin-top: 8px; }
.ap-desc-box { background: #21262d; border-radius: 6px; padding: 10px 12px; font-size: 11px; color: #8b949e; line-height: 1.6; margin-top: 12px; }
.ap-empty-state { text-align: center; padding: 36px 20px; color: #8b949e; border: 1px dashed #30363d; border-radius: 10px; margin-top: 8px; }
.ap-empty-title { font-size: 15px; font-weight: 500; color: #e6edf3; margin-bottom: 6px; }
section[data-testid="stMain"] [data-testid="stAlert"],
.stMain [data-testid="stAlert"] { background: #161b22 !important; border-color: #30363d !important; color: #e6edf3 !important; }
section[data-testid="stMain"] div[data-testid="stIframe"],
.stMain div[data-testid="stIframe"] { border: 1px solid #30363d !important; border-radius: 10px !important; overflow: hidden !important; background: #161b22 !important; }
</style>
"""


def _inject_ap_css() -> None:
    st.markdown(AP_CSS, unsafe_allow_html=True)


def _primary_label(labels: list[Any] | None) -> str:
    ls = [str(x) for x in (labels or [])]
    for lab in _LABEL_PRIORITY:
        if lab in ls:
            return lab
    return ls[0] if ls else "Node"


def _stable_id(props: dict[str, Any], primary: str) -> str:
    pid = props.get("id")
    if pid is not None and str(pid).strip():
        return str(pid).strip()
    if primary == "Actor":
        for k in ("name", "actor_id", "external_id"):
            v = props.get(k)
            if v is not None and str(v).strip():
                return str(v).strip()
    return "_anon"


def _node_key(labels: list[Any] | None, props: dict[str, Any]) -> str:
    pl = _primary_label(labels)
    return f"{pl}:{_stable_id(props, pl)}"


def _pill_color(primary: str) -> str:
    return _PILL_COLORS.get(primary, _DEFAULT_NODE)


def _pill_text(primary: str, props: dict[str, Any]) -> str:
    nid = props.get("id")
    if primary in ("CVE", "Technique"):
        return str(nid or props.get("name") or "?")
    if primary == "CWE":
        name = props.get("name") or ""
        name_s = (str(name)[:30] + "…") if len(str(name)) > 30 else str(name)
        base = str(nid or "?")
        return f"{base} — {name_s}" if name_s else base
    if primary == "Actor":
        return str(props.get("name") or nid or props.get("actor_id") or "?")
    return str(nid or "?")


def _pill_type_label(primary: str) -> str:
    if primary == "Technique":
        return "T"
    if primary == "CVE":
        return "CVE"
    if primary == "CWE":
        return "CWE"
    if primary == "Actor":
        return "Actor"
    return primary[:6].upper()


def _pill_class(primary: str) -> str:
    return {
        "CVE": "ap-pill ap-pill-cve",
        "CWE": "ap-pill ap-pill-cwe",
        "Technique": "ap-pill ap-pill-tech",
        "Actor": "ap-pill ap-pill-actor",
    }.get(primary, "ap-pill ap-pill-default")


def _pill_span(primary: str, props: dict[str, Any]) -> str:
    txt = html.escape(_pill_text(primary, props))
    ptype = _pill_type_label(primary)
    return (
        f'<span class="{_pill_class(primary)}">'
        f'<span class="ap-pill-type">{html.escape(ptype)}</span>{txt}</span>'
    )


def _severity_badge_html(sev: Any) -> str:
    if sev is None or str(sev).strip() == "":
        return ""
    s = str(sev).strip().upper()
    cls = {
        "CRITICAL": "ap-badge-critical",
        "HIGH": "ap-badge-high",
        "MEDIUM": "ap-badge-medium",
        "LOW": "ap-badge-low",
    }.get(s, "ap-badge-low")
    return f'<span class="{cls}">{html.escape(s)}</span>'


def _kev_badge_html() -> str:
    return '<span class="ap-badge-kev">KEV</span>'


def _tooltip_lines(props: dict[str, Any]) -> str:
    lines = [f"{html.escape(str(k))}: {html.escape(str(v))}" for k, v in sorted(props.items())]
    return "\n".join(lines)


def _parse_node(entry: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(entry, dict):
        return "Node", {}
    labels = entry.get("labels") or []
    props = entry.get("properties") or {}
    if not isinstance(props, dict):
        props = {}
    return _primary_label(labels if isinstance(labels, list) else []), props


def _error_message(code: int, data: Any, err: str) -> str:
    if isinstance(data, dict) and data.get("detail"):
        d = data["detail"]
        if isinstance(d, list):
            return "; ".join(str(x) for x in d)
        return str(d)
    if err:
        return err
    return f"Request failed (HTTP {code})."


def _unique_node_keys(paths: list[dict[str, Any]]) -> set[str]:
    keys: set[str] = set()
    for p in paths:
        nodes = p.get("nodes") or []
        if not isinstance(nodes, list):
            continue
        for n in nodes:
            labels = n.get("labels") if isinstance(n, dict) else []
            props = n.get("properties") if isinstance(n, dict) else {}
            if not isinstance(props, dict):
                props = {}
            keys.add(_node_key(labels if isinstance(labels, list) else [], props))
    return keys


def _kev_path_count(paths: list[dict[str, Any]], start_kind: str) -> int:
    if start_kind != "cve":
        return 0
    n = 0
    for p in paths:
        nodes = p.get("nodes") or []
        if not nodes or not isinstance(nodes, list):
            continue
        first = nodes[0]
        if not isinstance(first, dict):
            continue
        props = first.get("properties") or {}
        if isinstance(props, dict) and props.get("is_kev") is True:
            n += 1
    return n


def _build_pyvis_html(paths: list[dict[str, Any]]) -> str:
    net = Network(
        height="500px",
        width="100%",
        bgcolor="#1a1a1a",
        font_color="#ffffff",
        directed=True,
    )
    net.set_options(
        json.dumps(
            {
                "physics": {
                    "enabled": True,
                    "barnesHut": {"gravitationalConstant": -9000, "springLength": 120},
                },
                "edges": {
                    "arrows": {"to": {"enabled": True}},
                    "color": "#666666",
                    "font": {"color": "#e5e5e5", "size": 11, "strokeWidth": 0},
                    "smooth": {"type": "continuous"},
                },
                "nodes": {"font": {"color": "#ffffff"}},
                "interaction": {"hover": True},
            }
        )
    )

    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str, str]] = set()

    for p in paths:
        nodes = p.get("nodes") or []
        rels = p.get("rels") or []
        if not isinstance(nodes, list):
            continue
        for idx, raw in enumerate(nodes):
            if not isinstance(raw, dict):
                continue
            labels = raw.get("labels") or []
            props = raw.get("properties") or {}
            if not isinstance(labels, list):
                labels = []
            if not isinstance(props, dict):
                props = {}
            pl = _primary_label(labels)
            nid = _node_key(labels, props)
            if nid in seen_nodes:
                continue
            seen_nodes.add(nid)
            label = _pill_text(pl, props)
            color = _pill_color(pl)
            title = _tooltip_lines(props)
            net.add_node(nid, label=label, color=color, font={"color": "#ffffff"}, title=title)

        for k in range(len(nodes) - 1):
            a_raw, b_raw = nodes[k], nodes[k + 1]
            if not isinstance(a_raw, dict) or not isinstance(b_raw, dict):
                continue
            la, pa = a_raw.get("labels") or [], a_raw.get("properties") or {}
            lb, pb = b_raw.get("labels") or [], b_raw.get("properties") or {}
            if not isinstance(pa, dict):
                pa = {}
            if not isinstance(pb, dict):
                pb = {}
            id_a = _node_key(la if isinstance(la, list) else [], pa)
            id_b = _node_key(lb if isinstance(lb, list) else [], pb)
            rt = ""
            if isinstance(rels, list) and k < len(rels):
                r = rels[k]
                if isinstance(r, dict) and r.get("type"):
                    rt = str(r["type"])
            ek = (id_a, id_b, rt)
            if ek in seen_edges:
                continue
            seen_edges.add(ek)
            net.add_edge(id_a, id_b, label=rt or " ", title=rt or "")

    return net.generate_html()


def _prop_row(key: str, val: Any, *, crit_val: bool = False) -> str:
    vc = "ap-score-val-crit" if crit_val else ""
    return (
        f'<div class="ap-prop-row"><span class="ap-prop-key">{html.escape(key)}</span>'
        f'<span class="ap-prop-val {vc}">{html.escape(str(val))}</span></div>'
    )


def _render_detail_panel(start_kind: str, start_value: str, node0: dict[str, Any] | None) -> None:
    if not node0 or not isinstance(node0, dict):
        st.markdown(
            '<div class="ap-detail-panel"><p style="color:#8b949e;margin:0;">'
            "Select a path and click <strong>View details</strong> for the start node profile."
            "</p></div>",
            unsafe_allow_html=True,
        )
        return
    props = node0.get("properties") or {}
    if not isinstance(props, dict):
        props = {}
    head = str(props.get("id") or props.get("name") or start_value or "—")
    title = f"Start node — {html.escape(head)}"

    if start_kind == "cve":
        score = props.get("cvss_score")
        sev = str(props.get("cvss_severity") or "").strip().upper()
        sev_crit = sev == "CRITICAL"
        score_s = html.escape(str(score)) if score is not None else "—"
        sev_s = html.escape(sev) if sev else "—"
        parts: list[str] = [
            "<div class=\"ap-detail-panel\">",
            f'<div class="ap-detail-title">{title}</div>',
            '<div class="ap-score-row">',
            '<div class="ap-score-card">',
            '<div class="ap-score-label">CVSS score</div>',
            f'<div class="ap-score-val{" ap-score-val-crit" if sev_crit else ""}">{score_s}</div>',
            "</div>",
            '<div class="ap-score-card">',
            '<div class="ap-score-label">Severity</div>',
            f'<div class="ap-score-val{" ap-score-val-crit" if sev_crit else ""}" '
            f'style="font-size:14px;padding-top:4px">{sev_s}</div>',
            "</div></div>",
        ]
        for label, key in [
            ("Attack vector", "attack_vector"),
            ("Attack complexity", "attack_complexity"),
            ("Privileges required", "privileges_required"),
            ("User interaction", "user_interaction"),
            ("Scope", "scope"),
            ("Confidentiality impact", "confidentiality_impact"),
            ("Integrity impact", "integrity_impact"),
            ("Has exploit ref", "has_exploit_ref"),
        ]:
            v = props.get(key)
            if v is not None and str(v) != "":
                crit = key == "has_exploit_ref" and str(v).lower() in ("true", "1", "yes")
                parts.append(_prop_row(label, v, crit_val=crit))
        if props.get("is_kev") is True:
            parts.append('<div class="ap-kev-section"><div class="ap-kev-title">CISA KEV</div>')
            for lab, ky in [
                ("Vendor", "kev_vendor_project"),
                ("Product", "kev_product"),
                ("Date added", "kev_date_added"),
                ("Due date", "kev_due_date"),
                ("Ransomware", "kev_ransomware_use"),
            ]:
                v = props.get(ky)
                if v is not None and str(v) != "":
                    due_crit = ky == "kev_due_date"
                    parts.append(_prop_row(lab, v, crit_val=due_crit))
            req = props.get("kev_required_action")
            if req:
                parts.append(
                    f'<div class="ap-required-action">{html.escape(str(req))}</div>'
                )
            parts.append("</div>")
        desc = props.get("description_en")
        if desc:
            parts.append(
                f'<div class="ap-desc-box">{html.escape(str(desc))}</div>'
            )
        parts.append("</div>")
        st.markdown("".join(parts), unsafe_allow_html=True)
        return

    if start_kind == "actor":
        name = html.escape(str(props.get("name") or "—"))
        desc = props.get("description")
        al = props.get("aliases")
        body = ['<div class="ap-detail-panel">', f'<div class="ap-detail-title">{title}</div>']
        body.append(f'<h3 style="margin:0 0 8px 0;color:#e6edf3;font-size:18px;">{name}</h3>')
        if desc:
            body.append(f'<div class="ap-desc-box">{html.escape(str(desc))}</div>')
        if al:
            al_s = ", ".join(html.escape(str(x)) for x in al) if isinstance(al, list) else html.escape(str(al))
            body.append(
                '<div class="ap-prop-row"><span class="ap-prop-key">Aliases</span>'
                f'<span class="ap-prop-val">{al_s}</span></div>'
            )
        body.append("</div>")
        st.markdown("".join(body), unsafe_allow_html=True)
        return

    if start_kind == "technique":
        name = html.escape(str(props.get("name") or props.get("id") or "—"))
        tac = props.get("tactic_name") or props.get("tactic") or props.get("tactics")
        desc = props.get("description")
        body = ['<div class="ap-detail-panel">', f'<div class="ap-detail-title">{title}</div>']
        body.append(f'<h3 style="margin:0 0 8px 0;color:#e6edf3;font-size:18px;">{name}</h3>')
        if tac:
            body.append(
                f'<div class="ap-prop-row"><span class="ap-prop-key">Tactic</span>'
                f'<span class="ap-prop-val">{html.escape(str(tac))}</span></div>'
            )
        if desc:
            body.append(f'<div class="ap-desc-box">{html.escape(str(desc))}</div>')
        body.append("</div>")
        st.markdown("".join(body), unsafe_allow_html=True)
        return

    st.markdown(
        f'<div class="ap-detail-panel"><pre style="color:#e6edf3;">{html.escape(json.dumps(props, indent=2, default=str))}</pre></div>',
        unsafe_allow_html=True,
    )


def _metrics_html(
    path_count: int, uq: int, mh_used: int, kev_n: int, *, kev_red: bool
) -> str:
    kcls = " ap-metric-val-red" if kev_red else ""
    return (
        '<div class="ap-metric-grid">'
        '<div class="ap-metric"><div class="ap-metric-label">Paths found</div>'
        f'<div class="ap-metric-val">{path_count}</div></div>'
        '<div class="ap-metric"><div class="ap-metric-label">Unique nodes</div>'
        f'<div class="ap-metric-val">{uq}</div></div>'
        '<div class="ap-metric"><div class="ap-metric-label">Max depth</div>'
        f'<div class="ap-metric-val">{mh_used}</div></div>'
        '<div class="ap-metric"><div class="ap-metric-label">KEV flagged</div>'
        f'<div class="ap-metric-val{kcls}">{kev_n}</div></div>'
        "</div>"
    )


st.set_page_config(page_title="CTI — Attack Path Explorer", layout="wide")

if "ap_view" not in st.session_state:
    st.session_state.ap_view = "list"
if "ap_last_code" not in st.session_state:
    st.session_state.ap_last_code = None
if "ap_last_data" not in st.session_state:
    st.session_state.ap_last_data = None
if "ap_last_err" not in st.session_state:
    st.session_state.ap_last_err = ""
if "ap_selected_path" not in st.session_state:
    st.session_state.ap_selected_path = None

_inject_ap_css()

base = render_api_sidebar()

st.markdown(
    '<div class="ap-page-header">'
    '<h1 class="ap-page-title">Attack path explorer</h1>'
    "<p class=\"ap-page-sub\">Trace threat paths from a CVE, actor, or technique "
    "through the knowledge graph</p></div>",
    unsafe_allow_html=True,
)
st.markdown("")  # keep spacing; title rendered via HTML for styling

with st.container(border=True):
    mode_options = ["CVE", "Actor", "Technique"]
    if hasattr(st, "segmented_control"):
        mode = st.segmented_control(
            "Start type",
            mode_options,
            default="CVE",
            key="ap_seg_mode",
            label_visibility="collapsed",
        )
    else:
        mode = st.radio(
            "Start type",
            mode_options,
            horizontal=True,
            key="ap_radio_mode",
        )
    from_cve = from_actor = from_technique = None
    row = st.columns([3, 1, 1, 1])
    with row[0]:
        if mode == "CVE":
            from_cve = st.text_input("CVE ID", value="CVE-2024-21413", key="ap_from_cve")
        elif mode == "Actor":
            from_actor = st.text_input("Actor", value="", key="ap_from_actor")
        else:
            from_technique = st.text_input("Technique ID", value="T1059", key="ap_from_technique")
    with row[1]:
        max_hops = st.number_input("Max hops", min_value=1, max_value=6, value=3, step=1)
    with row[2]:
        limit = st.number_input("Limit", min_value=1, max_value=25, value=10, step=1)
    with row[3]:
        st.write("")
        fetch = st.button("Fetch paths", type="primary", use_container_width=True)

if fetch:
    kwargs = {
        "from_cve": from_cve.strip() if from_cve else None,
        "from_actor": from_actor.strip() if from_actor else None,
        "from_technique": from_technique.strip() if from_technique else None,
        "max_hops": int(max_hops),
        "limit": int(limit),
    }
    if mode == "Actor" and not kwargs["from_actor"]:
        st.warning("Enter an actor name or id.")
    else:
        code, data, err = get_attack_path(base, **kwargs)
        st.session_state.ap_last_code = code
        st.session_state.ap_last_data = data
        st.session_state.ap_last_err = err or ""
        if code == 200 and isinstance(data, dict):
            pc = int(data.get("path_count") or 0)
            st.session_state.ap_selected_path = 0 if pc > 0 else None
        else:
            st.session_state.ap_selected_path = None

code = st.session_state.ap_last_code
data = st.session_state.ap_last_data
err = st.session_state.ap_last_err

if code is None:
    st.markdown(
        '<div class="ap-empty-state"><div class="ap-empty-title">Ready to explore</div>'
        "<p>Set parameters in the panel above and click <strong>Fetch paths</strong>.</p></div>",
        unsafe_allow_html=True,
    )
elif code == 0 or not isinstance(data, dict):
    st.error(_error_message(int(code or 0), data, err))
elif code != 200:
    st.error(_error_message(code, data, err))
else:
    paths = data.get("paths") or []
    if not isinstance(paths, list):
        paths = []
    path_count = int(data.get("path_count") or len(paths))
    start = data.get("start") or {}
    start_kind = str(start.get("kind") or "").lower()
    start_value = str(start.get("value") or "")

    if path_count == 0:
        st.markdown(
            '<div class="ap-empty-state">'
            '<div class="ap-empty-title">No paths found</div>'
            "<p>No paths found for this starting node. Try increasing max hops or check "
            "that the node exists in the graph.</p></div>",
            unsafe_allow_html=True,
        )
    else:
        uq = len(_unique_node_keys(paths))
        kev_n = _kev_path_count(paths, start_kind)
        mh_used = int(data.get("max_hops") or max_hops)

        st.markdown(
            _metrics_html(path_count, uq, mh_used, kev_n, kev_red=kev_n > 0),
            unsafe_allow_html=True,
        )

        cur_view = st.session_state.ap_view
        with st.container(border=True):
            st.caption("View")
            c1, c2 = st.columns(2)
            with c1:
                if st.button(
                    "List view",
                    type="primary" if cur_view == "list" else "secondary",
                    use_container_width=True,
                    key="ap_btn_list",
                ):
                    st.session_state.ap_view = "list"
            with c2:
                if st.button(
                    "Graph view",
                    type="primary" if cur_view == "graph" else "secondary",
                    use_container_width=True,
                    key="ap_btn_graph",
                ):
                    st.session_state.ap_view = "graph"

        cur_view = st.session_state.ap_view

        if cur_view == "graph":
            try:
                html_graph = _build_pyvis_html(paths)
                components.html(html_graph, height=520, scrolling=True)
            except Exception as ex:
                st.error(f"Could not render graph: {ex}")
        else:
            left, right = st.columns([1.15, 1])
            with left:
                sel = st.session_state.ap_selected_path
                for i, p in enumerate(paths):
                    if not isinstance(p, dict):
                        continue
                    nodes = p.get("nodes") or []
                    rels = p.get("rels") or []
                    if not isinstance(nodes, list):
                        nodes = []
                    if not isinstance(rels, list):
                        rels = []
                    depth = max(0, len(nodes) - 1)
                    first_props: dict[str, Any] = {}
                    if nodes and isinstance(nodes[0], dict):
                        fp = nodes[0].get("properties")
                        if isinstance(fp, dict):
                            first_props = fp

                    sel_cls = " ap-selected" if sel == i else ""
                    badges: list[str] = []
                    if first_props.get("is_kev") is True:
                        badges.append(_kev_badge_html())
                    sb = _severity_badge_html(first_props.get("cvss_severity"))
                    if sb:
                        badges.append(sb)
                    badge_html = (
                        f'<div class="ap-badge-row">{"".join(badges)}</div>' if badges else ""
                    )

                    chain: list[str] = ['<div class="ap-node-chain">']
                    for k, raw in enumerate(nodes):
                        if not isinstance(raw, dict):
                            continue
                        pl, pr = _parse_node(raw)
                        chain.append(_pill_span(pl, pr))
                        if k < len(nodes) - 1:
                            rt = ""
                            if k < len(rels) and isinstance(rels[k], dict):
                                rt = str(rels[k].get("type") or "")
                            chain.append(
                                f'<span class="ap-rel-arrow"> — {html.escape(rt)} —› </span>'
                            )
                    chain.append("</div>")

                    st.markdown(
                        f'<div class="ap-path-card{sel_cls}">'
                        '<div class="ap-path-meta">'
                        f'<span class="ap-path-num">Path {i + 1:02d} — depth {depth}</span>'
                        f"{badge_html}</div>"
                        f'{"".join(chain)}</div>',
                        unsafe_allow_html=True,
                    )
                    if st.button("View details", key=f"ap_sel_{i}"):
                        st.session_state.ap_selected_path = i

            with right:
                st.markdown(
                    '<div style="font-size:13px;font-weight:600;color:#8b949e;margin-bottom:8px;">'
                    "Detail</div>",
                    unsafe_allow_html=True,
                )
                sel = st.session_state.ap_selected_path
                node0 = None
                if sel is not None and 0 <= sel < len(paths):
                    pn = paths[sel]
                    if isinstance(pn, dict):
                        ns = pn.get("nodes") or []
                        if ns and isinstance(ns[0], dict):
                            node0 = ns[0]
                _render_detail_panel(start_kind, start_value, node0)
