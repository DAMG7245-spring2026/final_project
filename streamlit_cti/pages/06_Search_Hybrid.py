import streamlit as st
from lib.client import post_hybrid_search, render_api_sidebar

st.set_page_config(page_title="CTI — Hybrid search", layout="wide")

base = render_api_sidebar()
st.header("POST /search/advisory-chunks/hybrid")
query = st.text_area("query", value="ransomware advisory", height=80)
c1, c2, c3 = st.columns(3)
with c1:
    top_k = st.number_input("top_k", 1, 100, 10)
with c2:
    top_n = st.number_input("top_n", 1, 500, 50)
with c3:
    alpha = st.slider("alpha", 0.0, 1.0, 0.5, 0.05)
k_rrf = st.number_input("k_rrf", 1, 1000, 60)

if st.button("Search", type="primary"):
    body = {
        "query": query.strip(),
        "top_k": int(top_k),
        "top_n": int(top_n),
        "k_rrf": int(k_rrf),
        "alpha": float(alpha),
    }
    code, data, err = post_hybrid_search(base, body)
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
                    "rrf_score": r.get("rrf_score"),
                    "vector_score": r.get("vector_score"),
                    "bm25_score": r.get("bm25_score"),
                }
                for r in results
            ]
            st.dataframe(rows, use_container_width=True)
