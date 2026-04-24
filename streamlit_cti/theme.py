"""Shared Streamlit theme tokens derived from Attack Path page."""

from __future__ import annotations

import streamlit as st

GLOBAL_THEME_CSS = """
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

section[data-testid="stMain"] h1,
section[data-testid="stMain"] h2,
section[data-testid="stMain"] h3 {
  font-family: var(--display) !important;
  color: var(--text) !important;
}

section[data-testid="stMain"] label {
  color: var(--muted) !important;
  font-size: 11px !important;
  font-weight: 500 !important;
  text-transform: uppercase !important;
  letter-spacing: 0.08em !important;
  font-family: var(--mono) !important;
}

section[data-testid="stMain"] [data-baseweb="input"] input,
section[data-testid="stMain"] [data-baseweb="textarea"] textarea {
  background: var(--surface2) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 8px !important;
  color: var(--text) !important;
  font-family: var(--mono) !important;
  font-size: 13px !important;
}

section[data-testid="stMain"] [data-baseweb="input"] input:focus,
section[data-testid="stMain"] [data-baseweb="textarea"] textarea:focus {
  border-color: var(--blue) !important;
  box-shadow: 0 0 0 3px var(--blue-glow) !important;
}

section[data-testid="stMain"] [data-baseweb="select"] > div {
  background: var(--surface2) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 8px !important;
}

section[data-testid="stMain"] [data-baseweb="select"] input {
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
  color: var(--text) !important;
  font-family: var(--mono) !important;
  font-size: 13px !important;
}

section[data-testid="stMain"] [data-baseweb="select"] input:focus {
  box-shadow: none !important;
}

section[data-testid="stMain"] [data-baseweb="tag"] {
  background: color-mix(in srgb, var(--blue) 16%, var(--surface2)) !important;
  border: 1px solid color-mix(in srgb, var(--blue) 45%, var(--border2)) !important;
  color: var(--text) !important;
}

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

section[data-testid="stMain"] [data-testid="stVerticalBlockBorderWrapper"] {
  background: var(--surface) !important;
  border: 1px solid var(--border) !important;
  border-radius: 12px !important;
}

section[data-testid="stMain"] [data-testid="stAlert"] {
  background: var(--surface) !important;
  border-color: var(--border2) !important;
  color: var(--text) !important;
  border-radius: 10px !important;
}
</style>
"""


def inject_global_theme() -> None:
    """Inject app-wide theme styles for the current page render."""
    st.markdown(GLOBAL_THEME_CSS, unsafe_allow_html=True)
