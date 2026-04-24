"""CTI console — entry point. Run: poetry run streamlit run streamlit_cti/Home.py --server.port 8501"""

import streamlit as st
from lib.client import render_api_sidebar

st.set_page_config(
    page_title="CTI Graph Console",
    layout="wide",
    initial_sidebar_state="expanded",
)

render_api_sidebar()

st.title("CTI Graph Console")
st.markdown(
    """
This app calls your **FastAPI** backend for graph, NL query, weekly brief, and evaluation flows.

1. Set **API base URL** in the sidebar (default `http://127.0.0.1:8000`, or `CTI_API_BASE` from `.env`).
2. Start the API: `poetry run uvicorn app.main:app --reload --port 8000` — or use Docker Compose (includes **cti-ui** on port 8501).
3. Use the **pages** in the left sidebar: **Attack Path**, **NL Query**, **Weekly Brief**, and **Vector DB Eval** (titles may vary slightly).
"""
)
