import streamlit as st
from lib.client import get_weekly_brief, render_api_sidebar

st.set_page_config(page_title="CTI — Weekly brief (stub)", layout="wide")

base = render_api_sidebar()
st.header("GET /brief/weekly (stub)")
st.info("Backend returns **pending** until advisory subgraph exists in Neo4j.")
if st.button("Fetch brief", type="primary"):
    code, data, err = get_weekly_brief(base)
    st.caption(f"HTTP {code}")
    if err and code not in (200,):
        st.error(err)
    if data is not None:
        st.json(data)
