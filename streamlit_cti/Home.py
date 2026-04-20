"""CTI console — entry point. Run: poetry run streamlit run streamlit_cti/Home.py --server.port 8501"""

import streamlit as st
from lib.client import health, render_api_sidebar

st.set_page_config(
    page_title="CTI Graph Console",
    layout="wide",
    initial_sidebar_state="expanded",
)

base = render_api_sidebar()

st.title("CTI Graph Console")
st.markdown(
    """
This app calls your **FastAPI** backend (CVE, Actor, Technique, attack-path, search, stubs).

1. Set **API base URL** in the sidebar (default `http://127.0.0.1:8000`, or `CTI_API_BASE` from `.env`).
2. Start the API: `poetry run uvicorn app.main:app --reload --port 8000` — or use Docker Compose (includes **cti-ui** on port 8501).
3. Use the **pages** in the left sidebar to explore each endpoint.

**Note:** Hybrid search needs the API process to have built the BM25 index at startup; `/health` must be all-green if your demo requires every dependency.
"""
)

st.subheader("Backend connection")
if st.button("Ping API (`GET /health`)", type="primary"):
    code, data, err = health(base)
    if code == 200 and data:
        st.success(f"Connected — HTTP {code}. Overall status: **{data.get('status', 'unknown')}**")
        st.json(data)
    elif code == 503 and data:
        st.warning(f"API reachable but degraded — HTTP {code}. Check `dependencies` below.")
        st.json(data)
    elif code == 0:
        st.error(f"Could not reach API: {err}")
    else:
        st.error(f"HTTP {code}: {err or data}")
        if data is not None:
            st.json(data)
