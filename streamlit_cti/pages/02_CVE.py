import streamlit as st
from lib.client import get_cve, render_api_sidebar

st.set_page_config(page_title="CTI — CVE", layout="wide")

base = render_api_sidebar()
st.header("GET /cve/{cve_id}")
cve_id = st.text_input("CVE id", value="CVE-2024-21413", key="cve_input")
if st.button("Fetch CVE", type="primary"):
    code, data, err = get_cve(base, cve_id.strip())
    st.caption(f"HTTP {code}")
    if err and code not in (200,):
        st.error(err)
    if data is not None:
        st.json(data)
        w = data.get("weaknesses") or []
        if w:
            with st.expander("Weaknesses (table)"):
                st.dataframe(w, use_container_width=True)
