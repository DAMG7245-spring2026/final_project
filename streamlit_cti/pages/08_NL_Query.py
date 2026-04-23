import streamlit as st
import requests

st.set_page_config(page_title="CTI — NL Query", layout="wide")

st.header("Natural Language Query")

q = st.text_area("Question", value="Which malware targets healthcare organizations?", height=100)

if st.button("Send", type="primary"):
    def stream_response():
        with requests.post(
            "http://localhost:8000/query/stream",
            json={"question": q.strip()},
            stream=True,
            timeout=120,
        ) as resp:
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=None):
                if chunk:
                    yield chunk.decode("utf-8")

    try:
        st.write_stream(stream_response())
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to backend at http://localhost:8000")
    except Exception as e:
        st.error(str(e))
