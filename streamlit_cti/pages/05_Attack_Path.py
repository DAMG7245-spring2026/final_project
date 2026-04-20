import streamlit as st
from lib.client import get_attack_path, render_api_sidebar

st.set_page_config(page_title="CTI — Attack path", layout="wide")

base = render_api_sidebar()
st.header("GET /graph/attack-path")
st.caption("Provide exactly one start: CVE, Actor, or Technique.")

mode = st.radio("Start type", ("CVE", "Actor", "Technique"), horizontal=True)
from_cve = from_actor = from_technique = None
if mode == "CVE":
    from_cve = st.text_input("from_cve", value="CVE-2024-21413")
elif mode == "Actor":
    from_actor = st.text_input("from_actor", value="")
else:
    from_technique = st.text_input("from_technique", value="T1059")

col1, col2 = st.columns(2)
with col1:
    max_hops = st.slider("max_hops", 1, 6, 3)
with col2:
    limit = st.slider("limit", 1, 25, 10)

if st.button("Fetch paths", type="primary"):
    kwargs = {
        "from_cve": from_cve.strip() if from_cve else None,
        "from_actor": from_actor.strip() if from_actor else None,
        "from_technique": from_technique.strip() if from_technique else None,
        "max_hops": max_hops,
        "limit": limit,
    }
    if mode == "Actor" and not kwargs["from_actor"]:
        st.warning("Enter from_actor.")
    else:
        code, data, err = get_attack_path(base, **kwargs)
        st.caption(f"HTTP {code}")
        if err and code not in (200,):
            st.error(err)
        if data is not None:
            st.json(data)
