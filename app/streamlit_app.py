"""Streamlit UI: CISA report types overview + advisories filtered by document_type."""
import os

import httpx
import pandas as pd
import streamlit as st


API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000")


REPORT_TYPES: dict[str, dict] = {
    "MAR": {
        "label": "Malware Analysis Report (MAR)",
        "description": (
            "Deep technical reverse-engineering of a specific malware sample. "
            "Organized per-hash with YARA/Sigma detection content and MITRE mappings."
        ),
        "sections": [
            "Summary", "Findings", "Relationship",
            "Detection", "MITRE", "Recommendation",
        ],
    },
    "ANALYSIS_REPORT": {
        "label": "Analysis Report (AR)",
        "description": (
            "Mid-depth malware / campaign analysis. Focuses on metadata, delivery, "
            "functionality and defender mitigations."
        ),
        "sections": [
            "Summary", "Malware Metadata", "Malware Delivery",
            "Malware Functionality", "Detection", "MITRE",
            "Mitigation", "Appendix",
        ],
    },
    "JOINT_CSA": {
        "label": "Joint Cybersecurity Advisory",
        "description": (
            "Multi-agency (CISA + FBI/NSA/partners) advisory on threat actor "
            "activity. Includes TTPs, IoCs, CVEs and mitigation guidance."
        ),
        "sections": [
            "Summary", "Background", "Technical Detail",
            "CVE", "MITRE", "IoC",
            "Detection", "Mitigation", "Resource",
        ],
    },
    "STOPRANSOMWARE": {
        "label": "#StopRansomware Advisory",
        "description": (
            "Ransomware-variant focused joint advisory. Same shape as Joint CSA "
            "but scoped to a specific ransomware group / family."
        ),
        "sections": [
            "Summary", "Background", "Technical Detail",
            "CVE", "MITRE", "IoC",
            "Detection", "Mitigation", "Resource",
        ],
    },
    "CSA": {
        "label": "Cybersecurity Advisory (CSA)",
        "description": (
            "Single-agency CISA advisory. Same section taxonomy as Joint CSA, "
            "narrower authorship."
        ),
        "sections": [
            "Summary", "Background", "Technical Detail",
            "CVE", "MITRE", "IoC",
            "Detection", "Mitigation", "Resource",
        ],
    },
    "IR_LESSONS": {
        "label": "Incident Response Lessons Learned",
        "description": (
            "Post-incident retrospective from a real engagement. Adds a Timeline "
            "of key events and lessons-learned findings."
        ),
        "sections": [
            "IoC", "MITRE", "CVE",
            "Detection", "Technical Detail", "Lessons",
            "Mitigation", "Background", "Resource",
            "Summary", "Timeline",
        ],
    },
}


@st.cache_data(ttl=300)
def fetch_advisories(document_type: str, limit: int = 5) -> dict:
    resp = httpx.get(
        f"{API_BASE_URL}/advisories",
        params={"document_type": document_type, "limit": limit},
        timeout=30.0,
    )
    resp.raise_for_status()
    return resp.json()


@st.cache_data(ttl=300)
def fetch_advisory_chunks(document_type: str, limit: int = 5) -> dict:
    resp = httpx.get(
        f"{API_BASE_URL}/advisories/chunks",
        params={"document_type": document_type, "limit": limit},
        timeout=30.0,
    )
    resp.raise_for_status()
    return resp.json()


def render_report_types() -> None:
    st.subheader("CISA Report Types")
    st.caption(
        "Each document_type uses its own chunking strategy and canonical section taxonomy."
    )
    type_keys = list(REPORT_TYPES.keys())
    for row_start in range(0, len(type_keys), 2):
        cols = st.columns(2)
        for col, key in zip(cols, type_keys[row_start:row_start + 2]):
            info = REPORT_TYPES[key]
            with col:
                with st.container(border=True):
                    st.markdown(f"#### {info['label']}")
                    st.markdown(f"`document_type = {key}`")
                    st.write(info["description"])
                    st.markdown("**Sections:**")
                    st.markdown(" ".join(f"`{s}`" for s in info["sections"]))


def render_advisories_by_type() -> None:
    st.subheader("Advisories by document_type")
    st.caption(f"Backend: `{API_BASE_URL}/advisories`")

    options = list(REPORT_TYPES.keys())
    selected = st.selectbox(
        "Select document_type",
        options=options,
        format_func=lambda k: f"{k} — {REPORT_TYPES[k]['label']}",
    )

    try:
        payload = fetch_advisories(selected, limit=5)
    except httpx.HTTPStatusError as e:
        st.error(f"API error {e.response.status_code}: {e.response.text}")
        return
    except httpx.HTTPError as e:
        st.error(f"Failed to reach backend at {API_BASE_URL}: {e}")
        return

    rows = payload.get("rows", [])
    columns = payload.get("columns", [])
    st.caption(f"Returned {payload.get('count', 0)} row(s).")

    if not rows:
        st.info(f"No advisories with document_type = {selected}.")
        return

    df = pd.DataFrame(rows, columns=columns)
    st.dataframe(df, width="stretch", hide_index=True)


def render_chunks_by_type() -> None:
    st.subheader("Advisory Chunks by document_type")
    st.caption(f"Backend: `{API_BASE_URL}/advisories/chunks`")

    options = list(REPORT_TYPES.keys())
    selected = st.selectbox(
        "Select document_type ",
        options=options,
        format_func=lambda k: f"{k} — {REPORT_TYPES[k]['label']}",
        key="chunks_doc_type",
    )

    try:
        payload = fetch_advisory_chunks(selected, limit=30)
    except httpx.HTTPStatusError as e:
        st.error(f"API error {e.response.status_code}: {e.response.text}")
        return
    except httpx.HTTPError as e:
        st.error(f"Failed to reach backend at {API_BASE_URL}: {e}")
        return

    rows = payload.get("rows", [])
    columns = payload.get("columns", [])
    st.caption(f"Returned {payload.get('count', 0)} chunk(s).")

    if not rows:
        st.info(f"No chunks for document_type = {selected}.")
        return

    df = pd.DataFrame(rows, columns=columns)
    st.dataframe(df, width="stretch", hide_index=True)


def main() -> None:
    st.set_page_config(page_title="CISA Reports Explorer", layout="wide")
    st.title("CISA Reports Explorer")
    render_report_types()
    st.divider()
    render_advisories_by_type()
    st.divider()
    render_chunks_by_type()


if __name__ == "__main__":
    main()
