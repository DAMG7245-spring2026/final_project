import streamlit as st
from lib.client import post_query, render_api_sidebar

st.set_page_config(page_title="CTI — NL Query (stub)", layout="wide")

base = render_api_sidebar()
st.header("POST /query (stub)")
st.info("Backend returns **pending** until unstructured advisory data is in Neo4j.")
q = st.text_area("Question (reserved)", value="Which actors exploit CVE-2024-21413?", height=100)
if st.button("Send", type="primary"):
    code, data, err = post_query(base, q.strip())
    st.caption(f"HTTP {code}")
    if err and code not in (200,):
        st.error(err)
    if data is not None:
        st.json(data)
