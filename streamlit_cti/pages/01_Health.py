import streamlit as st
from lib.client import health, render_api_sidebar

st.set_page_config(page_title="CTI — Health", layout="wide")

base = render_api_sidebar()
st.header("GET /health")
if st.button("Fetch health", type="primary"):
    code, data, err = health(base)
    st.caption(f"HTTP {code}")
    if err and code != 200:
        st.error(err)
    if data is not None:
        st.json(data)
