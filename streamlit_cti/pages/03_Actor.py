import streamlit as st
from lib.client import get_actor, render_api_sidebar

st.set_page_config(page_title="CTI — Actor", layout="wide")

base = render_api_sidebar()
st.header("GET /actor/{actor_id}")
actor_id = st.text_input("Actor id / name / external_id", value="", key="actor_input")
if st.button("Fetch actor", type="primary"):
    if not actor_id.strip():
        st.warning("Enter an actor identifier.")
    else:
        code, data, err = get_actor(base, actor_id.strip())
        st.caption(f"HTTP {code}")
        if err and code not in (200,):
            st.error(err)
        if data is not None:
            st.json(data)
