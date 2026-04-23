import streamlit as st
import requests

st.set_page_config(page_title="CTI — NL Query", layout="wide")

st.header("Natural Language Query")

q = st.text_area("Question", value="Which malware targets healthcare organizations?", height=100)

if st.button("Send", type="primary"):
    with st.spinner("Querying..."):
        try:
            resp = requests.post(
                "http://localhost:8000/query",
                json={"question": q.strip()},
                headers={"accept": "application/json", "Content-Type": "application/json"},
                timeout=60,
            )
            st.caption(f"HTTP {resp.status_code}")
            if resp.ok:
                data = resp.json()
                if "answer" in data:
                    st.markdown(data["answer"])
                else:
                    st.json(data)
            else:
                st.error(resp.text)
        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to backend at http://localhost:8000")
        except Exception as e:
            st.error(str(e))
