"""Attack Path Explorer — dynamic, interactive Streamlit page."""

from __future__ import annotations

import html
import json
from typing import Any

import streamlit as st
import streamlit.components.v1 as components
from lib.client import get_attack_path, get_graph_actors, render_api_sidebar
from pyvis.network import Network

# ── constants ────────────────────────────────────────────────────────────────
_LABEL_PRIORITY = ("CVE", "CWE", "Technique", "Tactic", "Actor", "Malware", "Campaign", "Other")
_PILL_COLORS = {
    "CVE":       "#E24B4A",
    "CWE":       "#378ADD",
    "Technique": "#7F77DD",
    "Tactic":    "#1D9E75",
    "Actor":     "#BA7517",
    "Malware":   "#D85A30",
    "Campaign":  "#D4537E",
    "Other":     "#6B8A9E",
}
_DEFAULT_NODE_COLOR = "#888780"

# ── CSS ───────────────────────────────────────────────────────────────────────
AP_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Syne:wght@400;500;600;700&display=swap');

:root {
  --bg: #080c12;
  --surface: #0f1520;
  --surface2: #161d2e;
  --surface3: #1c2640;
  --border: #1e2d45;
  --border2: #263550;
  --text: #dce8f5;
  --muted: #6b85a8;
  --subtle: #334d6e;
  --red: #f85149;
  --red-glow: rgba(248,81,73,0.15);
  --blue: #4d9de0;
  --blue-glow: rgba(77,157,224,0.12);
  --purple: #9d7fe8;
  --purple-glow: rgba(157,127,232,0.12);
  --amber: #d4952a;
  --amber-glow: rgba(212,149,42,0.12);
  --green: #2ecc8a;
  --green-glow: rgba(46,204,138,0.12);
  --coral: #e0684a;
  --pink: #c45490;
  --mono: 'JetBrains Mono', monospace;
  --display: 'Syne', sans-serif;
}

/* ── app shell ── */
.stApp { background: var(--bg) !important; }
section[data-testid="stMain"] .block-container {
  font-family: var(--display) !important;
  background: var(--bg) !important;
  color: var(--text) !important;
  padding-top: 1.5rem !important;
  max-width: 1280px !important;
}
section[data-testid="stSidebar"] {
  background: var(--surface) !important;
  border-right: 1px solid var(--border) !important;
}

/* ── typography ── */
section[data-testid="stMain"] h1 {
  font-family: var(--display) !important;
  font-size: 26px !important;
  font-weight: 700 !important;
  letter-spacing: -0.03em !important;
  color: var(--text) !important;
  border: none !important;
}
section[data-testid="stMain"] label {
  color: var(--muted) !important;
  font-size: 11px !important;
  font-weight: 500 !important;
  text-transform: uppercase !important;
  letter-spacing: 0.08em !important;
  font-family: var(--mono) !important;
}

/* ── inputs ── */
section[data-testid="stMain"] [data-baseweb="input"] input {
  background: var(--surface2) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 8px !important;
  color: var(--text) !important;
  font-family: var(--mono) !important;
  font-size: 13px !important;
}
section[data-testid="stMain"] [data-baseweb="input"] input:focus {
  border-color: var(--blue) !important;
  box-shadow: 0 0 0 3px var(--blue-glow) !important;
}

/* ── buttons ── */
section[data-testid="stMain"] button[kind="primary"] {
  background: linear-gradient(135deg, #3a7bd5 0%, #2d5fa8 100%) !important;
  color: #fff !important;
  border: none !important;
  border-radius: 8px !important;
  font-family: var(--display) !important;
  font-weight: 600 !important;
  letter-spacing: 0.02em !important;
}
section[data-testid="stMain"] button[kind="secondary"] {
  background: var(--surface2) !important;
  color: var(--muted) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 8px !important;
  font-family: var(--display) !important;
}
section[data-testid="stMain"] button[kind="secondary"]:hover {
  border-color: var(--blue) !important;
  color: var(--text) !important;
}

/* ── containers ── */
section[data-testid="stMain"] [data-testid="stVerticalBlockBorderWrapper"] {
  background: var(--surface) !important;
  border: 1px solid var(--border) !important;
  border-radius: 12px !important;
}

/* ── alerts ── */
section[data-testid="stMain"] [data-testid="stAlert"] {
  background: var(--surface) !important;
  border-color: var(--border2) !important;
  color: var(--text) !important;
  border-radius: 10px !important;
}

/* ── iframes (pyvis) ── */
section[data-testid="stMain"] div[data-testid="stIframe"] {
  border: 1px solid var(--border2) !important;
  border-radius: 12px !important;
  overflow: hidden !important;
}

/* ── page header ── */
.ap-header {
  margin-bottom: 24px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--border);
}
.ap-title {
  font-family: var(--display);
  font-size: 26px;
  font-weight: 700;
  letter-spacing: -0.03em;
  color: var(--text);
  margin-bottom: 4px;
}
.ap-sub {
  font-size: 13px;
  color: var(--muted);
  font-family: var(--mono);
}
.ap-breadcrumb {
  font-size: 11px;
  color: var(--subtle);
  font-family: var(--mono);
  margin-bottom: 8px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

/* ── search panel ── */
.ap-search-panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 20px 22px;
  margin-bottom: 20px;
  position: relative;
  overflow: hidden;
}
.ap-search-panel::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, var(--blue), var(--purple), var(--blue));
}

/* ── metrics ── */
.ap-metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin: 20px 0;
}
.ap-metric {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px 18px;
  position: relative;
  overflow: hidden;
  transition: border-color 0.2s;
}
.ap-metric:hover { border-color: var(--border2); }
.ap-metric::after {
  content: '';
  position: absolute;
  bottom: 0; left: 0; right: 0;
  height: 2px;
  background: var(--accent-color, var(--blue));
  opacity: 0.4;
}
.ap-metric-label {
  font-size: 10px;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 8px;
  font-family: var(--mono);
}
.ap-metric-val {
  font-size: 28px;
  font-weight: 700;
  font-family: var(--mono);
  color: var(--text);
  line-height: 1;
}
.ap-metric-val-red { color: var(--red) !important; }
.ap-metric-sub {
  font-size: 11px;
  color: var(--muted);
  font-family: var(--mono);
  margin-top: 4px;
}

/* ── view toggle ── */
.ap-view-toggle {
  display: flex;
  gap: 0;
  border: 1px solid var(--border2);
  border-radius: 8px;
  overflow: hidden;
  width: fit-content;
  margin-bottom: 18px;
}
.ap-view-btn {
  background: transparent;
  border: none;
  padding: 8px 20px;
  font-size: 12px;
  font-weight: 600;
  color: var(--muted);
  cursor: pointer;
  font-family: var(--display);
  letter-spacing: 0.04em;
  transition: all 0.15s;
}
.ap-view-btn.active {
  background: var(--surface2);
  color: var(--text);
}
.ap-view-btn:hover:not(.active) { color: var(--text); }

/* ── path card ── */
.ap-path-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px 18px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: all 0.2s;
  position: relative;
  overflow: hidden;
}
.ap-path-card:hover {
  border-color: var(--border2);
  background: var(--surface2);
}
.ap-path-card.ap-selected {
  border-color: var(--blue) !important;
  background: rgba(77,157,224,0.05) !important;
}
.ap-path-card.ap-selected::before {
  content: '';
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 3px;
  background: var(--blue);
}
.ap-path-meta {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  flex-wrap: wrap;
  gap: 8px;
}
.ap-path-num {
  font-size: 11px;
  font-weight: 600;
  color: var(--muted);
  font-family: var(--mono);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.ap-badge-row { display: flex; gap: 5px; flex-wrap: wrap; align-items: center; }

/* ── node chain ── */
.ap-node-chain {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 2px;
}
.ap-pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 5px 11px;
  border-radius: 22px;
  font-size: 12px;
  font-weight: 500;
  font-family: var(--mono);
  transition: all 0.15s;
}
.ap-pill:hover { transform: translateY(-1px); }
.ap-pill-type {
  font-size: 9px;
  opacity: 0.7;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.ap-pill-CVE       { background: rgba(248,81,73,0.14);  color: #ff8b82; border: 1px solid rgba(248,81,73,0.28); }
.ap-pill-CWE       { background: rgba(77,157,224,0.14); color: #79c3ff; border: 1px solid rgba(77,157,224,0.28); }
.ap-pill-Technique { background: rgba(157,127,232,0.14);color: #c4aaff; border: 1px solid rgba(157,127,232,0.28); }
.ap-pill-Tactic    { background: rgba(46,204,138,0.14); color: #5df5b0; border: 1px solid rgba(46,204,138,0.28); }
.ap-pill-Actor     { background: rgba(212,149,42,0.14); color: #f0b84a; border: 1px solid rgba(212,149,42,0.28); }
.ap-pill-Malware   { background: rgba(224,104,74,0.14); color: #ff9977; border: 1px solid rgba(224,104,74,0.28); }
.ap-pill-Campaign  { background: rgba(196,84,144,0.14); color: #f090c0; border: 1px solid rgba(196,84,144,0.28); }
.ap-pill-Other     { background: rgba(107,138,158,0.14); color: #9eb8cc; border: 1px solid rgba(107,138,158,0.32); }
.ap-pill-default   { background: var(--surface2); color: #c9d1d9; border: 1px solid var(--border2); }
.ap-rel-arrow {
  color: var(--subtle);
  font-size: 11px;
  font-family: var(--mono);
  white-space: nowrap;
}

/* ── badges ── */
.ap-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 9px;
  border-radius: 5px;
  font-size: 11px;
  font-weight: 700;
  font-family: var(--mono);
  letter-spacing: 0.04em;
}
.ap-badge-kev      { background: rgba(248,81,73,0.16); color: var(--red); border: 1px solid rgba(248,81,73,0.35); }
.ap-badge-CRITICAL { background: rgba(248,81,73,0.12); color: #ff8b82; }
.ap-badge-HIGH     { background: rgba(212,149,42,0.12); color: #f0b84a; }
.ap-badge-MEDIUM   { background: rgba(77,157,224,0.12); color: #79c3ff; }
.ap-badge-LOW      { background: var(--surface2); color: var(--muted); }

/* ── detail panel ── */
.ap-detail {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px;
  position: sticky;
  top: 16px;
}
.ap-detail-hdr {
  font-size: 10px;
  font-weight: 700;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.12em;
  font-family: var(--mono);
  margin-bottom: 16px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}
.ap-scores {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin-bottom: 16px;
}
.ap-score-card {
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 8px;
  padding: 11px 13px;
}
.ap-score-label {
  font-size: 10px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 5px;
  font-family: var(--mono);
}
.ap-score-val {
  font-size: 22px;
  font-weight: 700;
  font-family: var(--mono);
  color: var(--text);
}
.ap-score-crit { color: var(--red) !important; }
.ap-prop-table { width: 100%; }
.ap-prop-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 5px 0;
  border-bottom: 1px solid rgba(30,45,69,0.8);
  font-size: 12px;
  gap: 8px;
}
.ap-prop-row:last-child { border-bottom: none; }
.ap-prop-key { color: var(--muted); white-space: nowrap; font-family: var(--mono); font-size: 11px; flex-shrink: 0; }
.ap-prop-val { color: var(--text); font-family: var(--mono); font-size: 11px; text-align: right; word-break: break-all; }
.ap-prop-val-crit { color: var(--red) !important; }
.ap-kev-box {
  background: rgba(248,81,73,0.06);
  border: 1px solid rgba(248,81,73,0.22);
  border-radius: 10px;
  padding: 14px;
  margin-top: 14px;
}
.ap-kev-hdr {
  font-size: 10px;
  font-weight: 700;
  color: var(--red);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-family: var(--mono);
  margin-bottom: 10px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.ap-kev-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--red);
  animation: pulse 2s infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}
.ap-required-action {
  background: rgba(248,81,73,0.1);
  border-left: 3px solid var(--red);
  border-radius: 0 8px 8px 0;
  padding: 9px 12px;
  font-size: 11px;
  color: #ffa7a3;
  line-height: 1.55;
  margin-top: 10px;
  font-family: var(--mono);
}
.ap-desc-box {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 11px 13px;
  font-size: 11px;
  color: var(--muted);
  line-height: 1.65;
  margin-top: 12px;
  font-family: var(--mono);
}
.ap-no-data {
  text-align: center;
  padding: 40px 16px;
  color: var(--muted);
  font-family: var(--mono);
  font-size: 12px;
  border: 1px dashed var(--border2);
  border-radius: 12px;
}
.ap-no-data-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  font-family: var(--display);
  margin-bottom: 6px;
}

/* ── risk bar ── */
.ap-risk-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid var(--border);
}
.ap-risk-label { font-size: 11px; color: var(--muted); font-family: var(--mono); white-space: nowrap; }
.ap-risk-track {
  flex: 1;
  height: 5px;
  background: var(--surface2);
  border-radius: 3px;
  overflow: hidden;
}
.ap-risk-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.5s ease;
}
.ap-risk-val { font-size: 11px; font-family: var(--mono); white-space: nowrap; font-weight: 600; }

/* ── empty / ready state ── */
.ap-ready {
  text-align: center;
  padding: 56px 24px;
  color: var(--muted);
}
.ap-ready-icon {
  width: 48px; height: 48px;
  border: 2px solid var(--border2);
  border-radius: 50%;
  margin: 0 auto 16px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.ap-ready-title {
  font-size: 18px;
  font-weight: 700;
  font-family: var(--display);
  color: var(--text);
  margin-bottom: 8px;
}
.ap-ready-sub { font-size: 13px; font-family: var(--mono); }
</style>
"""


# ── helpers ───────────────────────────────────────────────────────────────────
def _inject_css() -> None:
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
    if primary == "Other":
        name = props.get("name")
        if name is not None and str(name).strip():
            return str(name).strip()
        return "_anon"
    return "_anon"


def _node_key(labels: list[Any] | None, props: dict[str, Any]) -> str:
    pl = _primary_label(labels)
    return f"{pl}:{_stable_id(props, pl)}"


def _pill_color(primary: str) -> str:
    return _PILL_COLORS.get(primary, _DEFAULT_NODE_COLOR)


def _pill_text(primary: str, props: dict[str, Any]) -> str:
    nid = props.get("id")
    if primary in ("CVE", "Technique", "Tactic"):
        return str(nid or props.get("name") or "?")
    if primary == "CWE":
        name = props.get("name") or ""
        name_s = (str(name)[:28] + "…") if len(str(name)) > 28 else str(name)
        base = str(nid or "?")
        return f"{base} · {name_s}" if name_s else base
    if primary in ("Actor", "Malware", "Campaign", "Other"):
        return str(props.get("name") or nid or props.get("actor_id") or "?")
    return str(nid or "?")


def _parse_node(entry: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(entry, dict):
        return "Node", {}
    labels = entry.get("labels") or []
    props = entry.get("properties") or {}
    if not isinstance(props, dict):
        props = {}
    return _primary_label(labels if isinstance(labels, list) else []), props


def _unique_node_keys(paths: list[dict[str, Any]]) -> set[str]:
    keys: set[str] = set()
    for p in paths:
        for n in (p.get("nodes") or []):
            if isinstance(n, dict):
                keys.add(_node_key(n.get("labels"), n.get("properties") or {}))
    return keys


def _kev_path_count(paths: list[dict[str, Any]], start_kind: str) -> int:
    if start_kind != "cve":
        return 0
    return sum(
        1 for p in paths
        if isinstance(p, dict)
        and (p.get("nodes") or [{}])[0].get("properties", {}).get("is_kev") is True
    )


def _risk_score(props: dict[str, Any]) -> float:
    """Compute a 0-100 risk score from CVE properties."""
    score = 0.0
    cvss = props.get("cvss_score") or 0
    score += (float(cvss) / 10.0) * 50
    if props.get("is_kev"):
        score += 25
    if props.get("has_exploit_ref"):
        score += 15
    av = str(props.get("attack_vector") or "").upper()
    if av == "NETWORK":
        score += 10
    elif av == "ADJACENT":
        score += 5
    return min(score, 100.0)


def _risk_color(score: float) -> str:
    if score >= 80:
        return "#f85149"
    if score >= 60:
        return "#d4952a"
    if score >= 40:
        return "#4d9de0"
    return "#2ecc8a"


def _tooltip_lines(props: dict[str, Any]) -> str:
    return "\n".join(
        f"{html.escape(str(k))}: {html.escape(str(v))}"
        for k, v in sorted(props.items())
    )


def _error_message(code: int, data: Any, err: str) -> str:
    if isinstance(data, dict) and data.get("detail"):
        d = data["detail"]
        return "; ".join(str(x) for x in d) if isinstance(d, list) else str(d)
    return err or f"Request failed (HTTP {code})."


# ── pyvis graph ───────────────────────────────────────────────────────────────
def _build_pyvis_html(paths: list[dict[str, Any]]) -> str:
    net = Network(height="520px", width="100%", bgcolor="#0a0f1a",
                  font_color="#dce8f5", directed=True)
    net.set_options(json.dumps({
        "physics": {
            "enabled": True,
            "forceAtlas2Based": {
                "gravitationalConstant": -80,
                "centralGravity": 0.01,
                "springLength": 150,
                "springConstant": 0.08,
                "damping": 0.6,
            },
            "solver": "forceAtlas2Based",
            "minVelocity": 0.75,
        },
        "edges": {
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.7}},
            "color": {"color": "#263550", "highlight": "#4d9de0"},
            "font": {"color": "#6b85a8", "size": 10, "strokeWidth": 0},
            "smooth": {"type": "curvedCW", "roundness": 0.15},
            "width": 1.5,
        },
        "nodes": {
            "font": {"color": "#dce8f5", "size": 12, "face": "JetBrains Mono"},
            "borderWidth": 1.5,
            "shadow": False,
        },
        "interaction": {"hover": True, "tooltipDelay": 200},
    }))
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str, str]] = set()
    for p in paths:
        nodes = p.get("nodes") or []
        rels = p.get("rels") or []
        for raw in nodes:
            if not isinstance(raw, dict):
                continue
            labels = raw.get("labels") or []
            props = raw.get("properties") or {}
            pl = _primary_label(labels if isinstance(labels, list) else [])
            nid = _node_key(labels, props)
            if nid in seen_nodes:
                continue
            seen_nodes.add(nid)
            color = _pill_color(pl)
            net.add_node(
                nid,
                label=_pill_text(pl, props),
                color={"background": color + "26", "border": color,
                       "highlight": {"background": color + "40", "border": color}},
                font={"color": "#dce8f5"},
                title=_tooltip_lines(props),
                size=20 if pl == "CVE" else 16,
            )
        for k in range(len(nodes) - 1):
            a_raw, b_raw = nodes[k], nodes[k + 1]
            if not isinstance(a_raw, dict) or not isinstance(b_raw, dict):
                continue
            id_a = _node_key(a_raw.get("labels") or [], a_raw.get("properties") or {})
            id_b = _node_key(b_raw.get("labels") or [], b_raw.get("properties") or {})
            rt = (rels[k].get("type") or "") if isinstance(rels, list) and k < len(rels) and isinstance(rels[k], dict) else ""
            ek = (id_a, id_b, rt)
            if ek in seen_edges:
                continue
            seen_edges.add(ek)
            net.add_edge(id_a, id_b, label=rt or " ", title=rt or "")
    return net.generate_html()


# ── HTML builders ─────────────────────────────────────────────────────────────
def _metrics_html(path_count: int, uq: int, mh_used: int, kev_n: int) -> str:
    kev_cls = " ap-metric-val-red" if kev_n > 0 else ""
    items = [
        ("Paths found", str(path_count), "var(--blue)", ""),
        ("Unique nodes", str(uq), "var(--purple)", ""),
        ("Max depth", str(mh_used), "var(--green)", ""),
        ("KEV flagged", str(kev_n), "var(--red)", kev_cls),
    ]
    cards = ""
    for label, val, accent, extra_cls in items:
        cards += (
            f'<div class="ap-metric" style="--accent-color:{accent}">'
            f'<div class="ap-metric-label">{label}</div>'
            f'<div class="ap-metric-val{extra_cls}">{val}</div>'
            f'</div>'
        )
    return f'<div class="ap-metrics">{cards}</div>'


def _pill_span(primary: str, props: dict[str, Any]) -> str:
    txt = html.escape(_pill_text(primary, props))
    cls = f"ap-pill ap-pill-{primary}" if primary in _LABEL_PRIORITY else "ap-pill ap-pill-default"
    ptype = {"Technique": "T", "CVE": "CVE", "CWE": "CWE",
             "Actor": "Actor", "Malware": "Malware", "Tactic": "Tactic",
             "Campaign": "Camp", "Other": "Other"}.get(primary, primary[:5].upper())
    return (
        f'<span class="{cls}">'
        f'<span class="ap-pill-type">{html.escape(ptype)}</span>{txt}</span>'
    )


def _badge(text: str, cls: str) -> str:
    return f'<span class="ap-badge {cls}">{html.escape(text)}</span>'


def _path_card_html(i: int, p: dict[str, Any], selected: bool) -> str:
    nodes = p.get("nodes") or []
    rels = p.get("rels") or []
    depth = max(0, len(nodes) - 1)
    first_props: dict[str, Any] = {}
    if nodes and isinstance(nodes[0], dict):
        fp = nodes[0].get("properties")
        if isinstance(fp, dict):
            first_props = fp

    badges: list[str] = []
    if first_props.get("is_kev") is True:
        badges.append(_badge("KEV", "ap-badge-kev"))
    sev = str(first_props.get("cvss_severity") or "").strip().upper()
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        badges.append(_badge(sev, f"ap-badge-{sev}"))

    chain: list[str] = []
    for k, raw in enumerate(nodes):
        if not isinstance(raw, dict):
            continue
        pl, pr = _parse_node(raw)
        chain.append(_pill_span(pl, pr))
        if k < len(nodes) - 1:
            rt = (rels[k].get("type") or "") if k < len(rels) and isinstance(rels[k], dict) else ""
            chain.append(f'<span class="ap-rel-arrow"> ─ {html.escape(rt)} ─› </span>')

    sel_cls = " ap-selected" if selected else ""
    depth_label = f"depth {depth}" if depth > 0 else "direct"
    return (
        f'<div class="ap-path-card{sel_cls}">'
        f'<div class="ap-path-meta">'
        f'<span class="ap-path-num">Path {i + 1:02d} · {depth_label}</span>'
        f'<div class="ap-badge-row">{"".join(badges)}</div>'
        f'</div>'
        f'<div class="ap-node-chain">{"".join(chain)}</div>'
        f'</div>'
    )


def _prop_row_html(key: str, val: Any, crit: bool = False) -> str:
    vc = " ap-prop-val-crit" if crit else ""
    return (
        f'<div class="ap-prop-row">'
        f'<span class="ap-prop-key">{html.escape(key)}</span>'
        f'<span class="ap-prop-val{vc}">{html.escape(str(val))}</span>'
        f'</div>'
    )


def _detail_html(start_kind: str, start_value: str, node0: dict[str, Any] | None) -> str:
    if not node0 or not isinstance(node0, dict):
        return (
            '<div class="ap-detail">'
            '<div class="ap-no-data">'
            '<div class="ap-no-data-title">Select a path</div>'
            'Click "View details" on any path card to see the start node profile.'
            '</div></div>'
        )
    props = node0.get("properties") or {}
    head = str(props.get("id") or props.get("name") or start_value or "—")
    parts = [
        '<div class="ap-detail">',
        f'<div class="ap-detail-hdr">Start node · {html.escape(head)}</div>',
    ]

    if start_kind == "cve":
        score = props.get("cvss_score")
        sev = str(props.get("cvss_severity") or "").strip().upper()
        crit = sev == "CRITICAL"
        sc = " ap-score-crit" if crit else ""
        parts += [
            '<div class="ap-scores">',
            f'<div class="ap-score-card"><div class="ap-score-label">CVSS score</div>'
            f'<div class="ap-score-val{sc}">{html.escape(str(score) if score is not None else "—")}</div></div>',
            f'<div class="ap-score-card"><div class="ap-score-label">Severity</div>'
            f'<div class="ap-score-val{sc}" style="font-size:15px;padding-top:6px">'
            f'{html.escape(sev or "—")}</div></div>',
            "</div>",
        ]
        for label, key in [
            ("Attack vector", "attack_vector"),
            ("Complexity", "attack_complexity"),
            ("Privileges req.", "privileges_required"),
            ("User interaction", "user_interaction"),
            ("Scope", "scope"),
            ("Confidentiality", "confidentiality_impact"),
            ("Integrity", "integrity_impact"),
            ("Exploit ref", "has_exploit_ref"),
        ]:
            v = props.get(key)
            if v is not None and str(v) != "":
                is_crit = key == "has_exploit_ref" and str(v).lower() in ("true", "1", "yes")
                parts.append(_prop_row_html(label, v, crit=is_crit))

        rs = _risk_score(props)
        rc = _risk_color(rs)
        parts.append(
            f'<div class="ap-risk-bar">'
            f'<span class="ap-risk-label">Risk score</span>'
            f'<div class="ap-risk-track"><div class="ap-risk-fill" '
            f'style="width:{rs:.0f}%;background:{rc}"></div></div>'
            f'<span class="ap-risk-val" style="color:{rc}">{rs:.0f}</span>'
            f'</div>'
        )

        if props.get("is_kev") is True:
            parts.append(
                '<div class="ap-kev-box">'
                '<div class="ap-kev-hdr"><div class="ap-kev-dot"></div>CISA KEV</div>'
            )
            for lab, ky in [
                ("Vendor", "kev_vendor_project"),
                ("Product", "kev_product"),
                ("Date added", "kev_date_added"),
                ("Due date", "kev_due_date"),
                ("Ransomware", "kev_ransomware_use"),
            ]:
                v = props.get(ky)
                if v is not None and str(v) != "":
                    parts.append(_prop_row_html(lab, v, crit=(ky == "kev_due_date")))
            req = props.get("kev_required_action")
            if req:
                parts.append(f'<div class="ap-required-action">{html.escape(str(req))}</div>')
            parts.append("</div>")

        desc = props.get("description_en")
        if desc:
            parts.append(f'<div class="ap-desc-box">{html.escape(str(desc))}</div>')

    elif start_kind == "actor":
        name = html.escape(str(props.get("name") or "—"))
        parts.append(f'<h3 style="color:var(--text);font-family:var(--display);font-size:17px;margin:0 0 10px">{name}</h3>')
        for lab, ky in [("Aliases", "aliases"), ("Type", "type")]:
            v = props.get(ky)
            if v:
                vs = ", ".join(html.escape(str(x)) for x in v) if isinstance(v, list) else html.escape(str(v))
                parts.append(_prop_row_html(lab, vs))
        desc = props.get("description")
        if desc:
            parts.append(f'<div class="ap-desc-box">{html.escape(str(desc))}</div>')

    elif start_kind == "technique":
        name = html.escape(str(props.get("name") or props.get("id") or "—"))
        parts.append(f'<h3 style="color:var(--text);font-family:var(--display);font-size:17px;margin:0 0 10px">{name}</h3>')
        for lab, ky in [("Tactic", "tactic_name"), ("Platform", "platforms"), ("ID", "id")]:
            v = props.get(ky)
            if v:
                vs = ", ".join(html.escape(str(x)) for x in v) if isinstance(v, list) else html.escape(str(v))
                parts.append(_prop_row_html(lab, vs))
        desc = props.get("description")
        if desc:
            parts.append(f'<div class="ap-desc-box">{html.escape(str(desc))}</div>')

    else:
        parts.append(f'<pre style="color:var(--muted);font-size:11px;white-space:pre-wrap">{html.escape(json.dumps(props, indent=2, default=str))}</pre>')

    parts.append("</div>")
    return "".join(parts)


def _actor_dropdown_label(row: dict[str, Any]) -> str:
    dn = str(row.get("display_name") or row.get("value") or "").strip()
    aid = str(row.get("actor_id") or "").strip()
    if aid and aid.casefold() != dn.casefold():
        return f"{dn} ({aid})"
    return dn or str(row.get("value") or "?")


@st.cache_data(ttl=120, show_spinner="Loading actors…")
def _load_actor_dropdown_options(api_base: str) -> tuple[int, list[dict[str, Any]], str]:
    code, data, err = get_graph_actors(api_base)
    if code != 200 or not isinstance(data, dict):
        return code, [], err or ""
    raw = data.get("actors")
    if not isinstance(raw, list):
        return code, [], err or ""
    clean = [r for r in raw if isinstance(r, dict) and r.get("value")]
    return code, clean, ""


# ── page ──────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="CTI — Attack Path Explorer", layout="wide")

for k, v in [
    ("ap_view", "list"),
    ("ap_last_code", None),
    ("ap_last_data", None),
    ("ap_last_err", ""),
    ("ap_selected_path", None),
]:
    if k not in st.session_state:
        st.session_state[k] = v

_inject_css()
base = render_api_sidebar(show_url_input=False)

# ── header ────────────────────────────────────────────────────────────────────
st.markdown(
    '<div class="ap-header">'
    '<div class="ap-breadcrumb">CTI-Graph · Graph Intelligence</div>'
    '<div class="ap-title">Attack Path Explorer</div>'
    '<div class="ap-sub">Trace threat paths from a CVE, actor, or technique through the knowledge graph</div>'
    '</div>',
    unsafe_allow_html=True,
)

# ── search panel ──────────────────────────────────────────────────────────────
with st.container(border=True):
    mode_options = ["CVE", "Actor", "Technique"]
    if hasattr(st, "segmented_control"):
        mode = st.segmented_control(
            "Start type", mode_options, default="CVE",
            key="ap_seg_mode", label_visibility="collapsed",
        )
    else:
        mode = st.radio("Start type", mode_options, horizontal=True, key="ap_radio_mode")

    from_cve = from_actor = from_technique = None
    c_input, c_hops, c_limit, c_btn = st.columns([3, 1, 1, 1])
    with c_input:
        if mode == "CVE":
            from_cve = st.text_input("CVE ID", value="CVE-2024-21413", key="ap_from_cve")
        elif mode == "Actor":
            acode, arows, aerr = _load_actor_dropdown_options(base)
            if acode == 200 and arows:
                labels = ["— Select an actor —"] + [_actor_dropdown_label(r) for r in arows]

                def _actor_pick_label(i: int) -> str:
                    return labels[i]

                pick = st.selectbox(
                    "Actor",
                    options=list(range(len(arows) + 1)),
                    format_func=_actor_pick_label,
                    index=0,
                    key="ap_actor_select",
                )
                from_actor = "" if pick == 0 else str(arows[pick - 1].get("value") or "").strip()
            else:
                hint = f" (HTTP {acode})" if acode != 200 else ""
                st.caption(f"Could not load actor list{hint}. Enter a name or ID manually.")
                if aerr:
                    st.caption(aerr[:280])
                from_actor = st.text_input(
                    "Actor name or ID",
                    value="",
                    key="ap_from_actor_fallback",
                )
        else:
            from_technique = st.text_input("Technique ID", value="T1059", key="ap_from_tech")
    with c_hops:
        max_hops = st.number_input(
            "Max hops",
            min_value=1,
            max_value=6,
            value=3,
            step=1,
        )
    with c_limit:
        limit = st.number_input("Limit", min_value=1, max_value=25, value=10, step=1)
    with c_btn:
        st.write("")
        fetch = st.button("Fetch paths", type="primary", use_container_width=True)

# ── fetch ─────────────────────────────────────────────────────────────────────
if fetch:
    mh_i, lim_i = int(max_hops), int(limit)
    # Build exactly one start param from the active tab (session_state covers edge cases
    # where a widget return value and the submitted value can disagree on the same run).
    fc = fa = ft = None
    if mode == "CVE":
        fc = (st.session_state.get("ap_from_cve") or from_cve or "").strip() or None
    elif mode == "Actor":
        fa = (from_actor or "").strip() or None
    else:
        ft = (st.session_state.get("ap_from_tech") or from_technique or "").strip() or None
    kwargs: dict[str, Any] = {
        "from_cve": fc,
        "from_actor": fa,
        "from_technique": ft,
        "max_hops": mh_i,
        "limit": lim_i,
    }
    if mode == "Actor" and not kwargs["from_actor"]:
        st.warning("Select an actor from the list, or enter a name or ID if using manual input.")
        st.session_state.ap_last_code = None
        st.session_state.ap_last_data = None
        st.session_state.ap_last_err = ""
        st.session_state.ap_selected_path = None
    elif mode == "Technique" and not kwargs["from_technique"]:
        st.warning("Enter a technique ID (e.g. T1059) before fetching.")
        st.session_state.ap_last_code = None
        st.session_state.ap_last_data = None
        st.session_state.ap_last_err = ""
        st.session_state.ap_selected_path = None
    elif mode == "CVE" and not kwargs["from_cve"]:
        st.warning("Enter a CVE ID before fetching.")
        st.session_state.ap_last_code = None
        st.session_state.ap_last_data = None
        st.session_state.ap_last_err = ""
        st.session_state.ap_selected_path = None
    else:
        with st.spinner("Fetching attack paths…"):
            code, data, err = get_attack_path(base, **kwargs)
        st.session_state.ap_last_code = code
        st.session_state.ap_last_data = data
        st.session_state.ap_last_err = err or ""
        pc = int((data or {}).get("path_count") or 0) if code == 200 and isinstance(data, dict) else 0
        st.session_state.ap_selected_path = 0 if pc > 0 else None

# ── results ───────────────────────────────────────────────────────────────────
code = st.session_state.ap_last_code
data = st.session_state.ap_last_data
err = st.session_state.ap_last_err

if code is None:
    st.markdown(
        '<div class="ap-ready">'
        '<div class="ap-ready-icon">'
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6b85a8" stroke-width="2">'
        '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>'
        '</svg></div>'
        '<div class="ap-ready-title">Ready to explore</div>'
        '<div class="ap-ready-sub">Enter a CVE, actor, or technique above and click Fetch paths</div>'
        '</div>',
        unsafe_allow_html=True,
    )
elif code in (0, None) or not isinstance(data, dict):
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
        hint = (
            "Paths walk the graph in <strong>either direction</strong> from the technique, "
            "but must <strong>end</strong> on a non-Technique node. If this technique is "
            "isolated or only links to other techniques within the hop limit, try "
            "<strong>Max hops</strong> or another technique with CVE / actor / malware ties."
            if start_kind == "technique"
            else "Try increasing max hops, or verify this node exists in the graph."
        )
        st.markdown(
            '<div class="ap-no-data" style="margin-top:16px">'
            '<div class="ap-no-data-title">No paths found</div>'
            f"<p>Start: <code>{html.escape(start_value)}</code> ({html.escape(start_kind)}).</p>"
            f"<p>{hint}</p>"
            "</div>",
            unsafe_allow_html=True,
        )
    else:
        uq = len(_unique_node_keys(paths))
        kev_n = _kev_path_count(paths, start_kind)
        mh_used = int(data.get("max_hops") or max_hops)

        st.markdown(_metrics_html(path_count, uq, mh_used, kev_n), unsafe_allow_html=True)

        # view toggle
        cur_view = st.session_state.ap_view
        col_list, col_graph, _ = st.columns([1, 1, 4])
        with col_list:
            if st.button(
                "List view",
                type="primary" if cur_view == "list" else "secondary",
                use_container_width=True, key="ap_btn_list",
            ):
                st.session_state.ap_view = "list"
                st.rerun()
        with col_graph:
            if st.button(
                "Graph view",
                type="primary" if cur_view == "graph" else "secondary",
                use_container_width=True, key="ap_btn_graph",
            ):
                st.session_state.ap_view = "graph"
                st.rerun()

        cur_view = st.session_state.ap_view

        if cur_view == "graph":
            try:
                components.html(_build_pyvis_html(paths), height=540, scrolling=True)
                legend = " · ".join(f"{lab} ({c})" for lab, c in _PILL_COLORS.items())
                st.caption(f"Node colors — {legend}")
            except Exception as ex:
                st.error(f"Graph render error: {ex}")
        else:
            col_paths, col_detail = st.columns([1.1, 1])
            sel = st.session_state.ap_selected_path

            with col_paths:
                for i, p in enumerate(paths):
                    if not isinstance(p, dict):
                        continue
                    st.markdown(_path_card_html(i, p, selected=(sel == i)), unsafe_allow_html=True)
                    if st.button("View details", key=f"ap_sel_{i}"):
                        st.session_state.ap_selected_path = i
                        st.rerun()

            with col_detail:
                node0: dict[str, Any] | None = None
                if sel is not None and 0 <= sel < len(paths):
                    pn = paths[sel]
                    if isinstance(pn, dict):
                        ns = pn.get("nodes") or []
                        if ns and isinstance(ns[0], dict):
                            node0 = ns[0]
                st.markdown(_detail_html(start_kind, start_value, node0), unsafe_allow_html=True)