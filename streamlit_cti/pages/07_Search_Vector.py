import streamlit as st
from lib.client import post_vector_search, render_api_sidebar

st.set_page_config(page_title="CTI — Vector search", layout="wide")

base = render_api_sidebar()
st.header("POST /search/advisory-chunks")
query = st.text_area("query", value="phishing campaign", height=80)
top_k = st.number_input("top_k", 1, 100, 10)

if st.button("Search", type="primary"):
    body = {"query": query.strip(), "top_k": int(top_k)}
    code, data, err = post_vector_search(base, body)
    st.caption(f"HTTP {code}")
    if err and code not in (200,):
        st.error(err)
    if data is not None:
        st.json(data)
        results = data.get("results") or []
        if results:
            rows = [
                {
                    "chunk_id": r.get("chunk_id"),
                    "advisory_id": r.get("advisory_id"),
                    "score": r.get("score"),
                }
                for r in results
            ]
            st.dataframe(rows, use_container_width=True)
