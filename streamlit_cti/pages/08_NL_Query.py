import json
import os
import re

import requests
import streamlit as st
from streamlit_cti.theme import inject_global_theme

API_BASE = os.getenv("CTI_API_BASE", "http://localhost:8000")

st.set_page_config(page_title="CTI — NL Query", layout="wide")
inject_global_theme()


def _extract_match_vars(lines: list[str]) -> list[str]:
    vars_: list[str] = []
    for line in lines:
        if line.strip().upper().startswith("MATCH"):
            for v in re.findall(r'\((\w+)(?::\w+)?\)', line):
                if v not in vars_:
                    vars_.append(v)
            for v in re.findall(r'\[(\w+)(?::\w+)?\]', line):
                if v not in vars_:
                    vars_.append(v)
    return vars_ if vars_ else ["*"]


def _to_graph_cypher(cypher: str) -> str:
    """Rewrite RETURN to return nodes/rels so Neo4j Browser can render the graph."""
    lines = cypher.strip().splitlines()
    vars_ = _extract_match_vars(lines)
    out = []
    for line in lines:
        if line.strip().upper().startswith("RETURN"):
            out.append(f"RETURN {', '.join(vars_)}")
        else:
            out.append(line)
    return "\n".join(out)


EXAMPLE_QUESTIONS = [
    "What CVEs does Akira threat actor exploit?",
    "What malware does APT40 use?",
    "Which CVEs does the Andariel threat actor exploit?",
]

# --- session state init ---
if "nl_q" not in st.session_state:
    st.session_state["nl_q"] = "Which malware targets healthcare organizations?"

if "_nl_prefill" in st.session_state:
    st.session_state["nl_q"] = st.session_state.pop("_nl_prefill")

# --- UI ---
st.header("Natural Language Query")

st.markdown("**Example questions:**")
cols = st.columns(len(EXAMPLE_QUESTIONS))
for col, example in zip(cols, EXAMPLE_QUESTIONS):
    if col.button(example, use_container_width=True):
        st.session_state["_nl_prefill"] = example
        st.rerun()

q = st.text_area("Question", key="nl_q", height=100)

if st.button("Send", type="primary"):
    if not q.strip():
        st.warning("Please enter a question.")
        st.stop()

    route_placeholder = st.empty()
    cypher_placeholder = st.empty()
    answer_placeholder = st.empty()

    buffer = ""
    meta: dict | None = None
    answer_text = ""

    try:
        with requests.post(
            f"{API_BASE}/query/stream",
            json={"question": q.strip()},
            stream=True,
            timeout=120,
        ) as resp:
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=None):
                if not chunk:
                    continue
                text = chunk.decode("utf-8")

                if meta is None:
                    # accumulate until we have the first "\n" (metadata line)
                    buffer += text
                    if "\n" in buffer:
                        meta_line, rest = buffer.split("\n", 1)
                        try:
                            meta = json.loads(meta_line)
                        except json.JSONDecodeError:
                            # no metadata: treat everything as answer
                            meta = {}
                            rest = buffer

                        route = meta.get("route", "")
                        cypher = meta.get("cypher")

                        route_icon = {"graph": "🟢", "text": "🔵", "both": "🟣"}.get(route, "⚪")
                        route_placeholder.caption(f"{route_icon} Route: **{route}**")

                        if route in ("graph", "both") and cypher:
                            with cypher_placeholder.container():
                                with st.expander("Cypher (paste into Neo4j Browser to visualize graph)", expanded=True):
                                    st.code(_to_graph_cypher(cypher), language="cypher")

                        answer_text = rest
                        answer_placeholder.markdown(answer_text + "▌")
                else:
                    answer_text += text
                    answer_placeholder.markdown(answer_text + "▌")

        # stream ended without a metadata line → treat entire buffer as answer
        if meta is None and buffer:
            answer_placeholder.markdown(buffer)
        else:
            answer_placeholder.markdown(answer_text)

    except requests.exceptions.ConnectionError:
        st.error(f"Cannot connect to backend at {API_BASE}")
    except Exception as e:
        st.error(str(e))
