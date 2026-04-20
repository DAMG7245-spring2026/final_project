import streamlit as st
from lib.client import get_technique, render_api_sidebar

st.set_page_config(page_title="CTI — Technique", layout="wide")

base = render_api_sidebar()
st.header("GET /technique/{technique_id}")
tid = st.text_input("Technique id (e.g. T1059)", value="T1059", key="tech_input")
if st.button("Fetch technique", type="primary"):
    code, data, err = get_technique(base, tid.strip())
    st.caption(f"HTTP {code}")
    if err and code not in (200,):
        st.error(err)
    if data is not None:
        st.json(data)
