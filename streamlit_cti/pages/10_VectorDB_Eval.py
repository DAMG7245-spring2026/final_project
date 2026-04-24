"""VectorDB retrieval evaluation dashboard.

Renders the hybrid-search evaluation produced by
`notebooks/vectordb_eval.ipynb` with charts:

  * overall metrics by retriever config (grouped bar)
  * per-document_type hit@5 (heatmap)
  * hybrid alpha sweep (line)
  * classifier (MCP) agreement by gold doc_type (bar)
  * golden-set explorer + failure inspection

Data sources (bundled with the streamlit image so the page works inside Docker):
  * streamlit_cti/eval_artifacts/report_prompt.md  — tables from the eval run
  * streamlit_cti/eval_artifacts/golden.jsonl      — 125-query golden set
"""

from __future__ import annotations

import io
import json
import re
from collections import Counter
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

st.set_page_config(page_title="CTI — VectorDB Eval", layout="wide")

EVAL_DIR = Path(__file__).resolve().parents[1] / "eval_artifacts"
REPORT_PATH = EVAL_DIR / "report_prompt.md"
GOLDEN_PATH = EVAL_DIR / "golden.jsonl"


# ---------- loaders ---------------------------------------------------------


@st.cache_data(show_spinner=False)
def _read_report() -> str:
    return REPORT_PATH.read_text()


@st.cache_data(show_spinner=False)
def _read_golden() -> pd.DataFrame:
    rows = [json.loads(line) for line in GOLDEN_PATH.read_text().splitlines() if line.strip()]
    return pd.DataFrame(rows)


def _extract_code_blocks(md: str) -> list[str]:
    """Return every ```...``` block in order."""
    return re.findall(r"```(?:\w+)?\n(.*?)```", md, flags=re.DOTALL)


def _fixed_width_to_df(block: str) -> pd.DataFrame:
    """Parse a pandas ``DataFrame.to_string()`` dump back into a DataFrame.

    The report writes tables as plain text (no markdown pipes), which
    ``pd.read_fwf`` handles cleanly. The index column header ends up on a
    line by itself below the metric names; we skip it and let read_fwf
    infer column offsets from the metric header line.
    """
    lines = [ln for ln in block.splitlines() if ln.strip()]
    if not lines:
        return pd.DataFrame()
    header = lines[0]
    index_name_line = lines[1].rstrip() if len(lines) > 1 else ""
    # If second line looks like just an index label (no numbers), drop it.
    data_lines = lines[2:] if index_name_line and not re.search(r"\d", index_name_line) else lines[1:]
    buf = io.StringIO("\n".join([header, *data_lines]))
    df = pd.read_fwf(buf)
    # first column is the index label
    df = df.rename(columns={df.columns[0]: "_index"}).set_index("_index")
    for col in df.columns:
        coerced = pd.to_numeric(df[col], errors="coerce")
        if coerced.notna().any():
            df[col] = coerced
    return df


@st.cache_data(show_spinner=False)
def _parse_report() -> dict[str, pd.DataFrame | str]:
    md = _read_report()
    blocks = _extract_code_blocks(md)
    out: dict[str, pd.DataFrame | str] = {"markdown": md}
    # Expected order in the report:
    #   0 = overall metrics by config
    #   1 = classifier agreement by gold doc_type
    #   2 = per document_type hit@5 (wide)
    #   3 = alpha sweep
    names = ["overall", "classifier_gold", "per_doctype_hit5", "alpha_sweep"]
    for name, block in zip(names, blocks):
        try:
            out[name] = _fixed_width_to_df(block)
        except Exception as e:  # pylint: disable=broad-except
            out[name] = pd.DataFrame()
            out[f"{name}_error"] = str(e)
    return out


def _scalar_after(md: str, label: str) -> str | None:
    m = re.search(rf"{re.escape(label)}[^\n]*?\*\*([^*]+)\*\*", md)
    return m.group(1).strip() if m else None


def _scalar_backtick(md: str, label: str) -> str | None:
    m = re.search(rf"{re.escape(label)}[^\n]*?`([^`]+)`", md)
    return m.group(1).strip() if m else None


def _failure_lines(md: str) -> list[str]:
    m = re.search(r"## 6\. Failures[^\n]*\n(.*)", md, flags=re.DOTALL)
    if not m:
        return []
    tail = m.group(1)
    return [
        re.sub(r"^\s*-\s*", "", ln).strip()
        for ln in tail.splitlines()
        if ln.lstrip().startswith("-")
    ]


# ---------- page ------------------------------------------------------------

if not REPORT_PATH.exists():
    st.error(f"Report not found: `{REPORT_PATH}`. Run `notebooks/vectordb_eval.ipynb` first.")
    st.stop()

report = _parse_report()
golden = _read_golden() if GOLDEN_PATH.exists() else pd.DataFrame()
md = report["markdown"]

st.title("VectorDB Retrieval Evaluation")
st.caption(
    "Hybrid search benchmark on the `advisory_chunks` corpus — "
    "vector-only vs BM25 vs RRF-fused hybrid at multiple alphas, "
    "with oracle and MCP-simulated document-type routing."
)

gen_match = re.search(r"_Generated ([^_]+)_", md)
if gen_match:
    st.caption(f"Report generated: `{gen_match.group(1).strip()}`")

# ---- setup KPIs -----------------------------------------------------------

st.subheader("Setup")
golden_size_m = re.search(r"Golden set size:\s*\*\*(\d+)\*\*", md)
topk_m = re.search(r"Top-K:\s*(\d+)", md)
topn_m = re.search(r"Top-N pool:\s*(\d+)", md)
krrf_m = re.search(r"k_rrf:\s*(\d+)", md)
best_cfg = _scalar_backtick(md, "Best config by MRR:")
best_alpha = _scalar_backtick(md, "Best alpha by MRR:")

overall = report.get("overall", pd.DataFrame())
best_mrr = (
    f"{overall.loc[best_cfg, 'mrr']:.3f}"
    if isinstance(overall, pd.DataFrame) and best_cfg in overall.index and "mrr" in overall.columns
    else "—"
)

c = st.columns(5)
c[0].metric("Golden queries", golden_size_m.group(1) if golden_size_m else "—")
c[1].metric("Top-K / Top-N", f"{topk_m.group(1) if topk_m else '?'} / {topn_m.group(1) if topn_m else '?'}")
c[2].metric("k_rrf", krrf_m.group(1) if krrf_m else "—")
c[3].metric("Best config (MRR)", best_cfg or "—", delta=best_mrr if best_mrr != "—" else None)
c[4].metric("Best alpha (MRR)", best_alpha or "—")

st.caption("Embedding model: `snowflake-arctic-embed-l-v2.0` (1024-d).")

st.divider()

# ---- golden-set composition ------------------------------------------------

if not golden.empty:
    st.subheader("Golden set composition")
    cc = st.columns([2, 3])
    with cc[0]:
        doc_counts = (
            golden.groupby("document_type").size().rename("queries").reset_index()
        )
        doc_chart = (
            alt.Chart(doc_counts)
            .mark_bar()
            .encode(
                x=alt.X("queries:Q", title="queries"),
                y=alt.Y("document_type:N", sort="-x", title=None),
                color=alt.Color(
                    "document_type:N", legend=None, scale=alt.Scale(scheme="viridis")
                ),
                tooltip=["document_type", "queries"],
            )
            .properties(height=230, title="Queries per document_type")
        )
        st.altair_chart(doc_chart, use_container_width=True)
    with cc[1]:
        if "style_requested" in golden.columns:
            style_counts = Counter(golden["style_requested"].fillna("legacy"))
            style_df = pd.DataFrame(
                {"style": list(style_counts), "queries": list(style_counts.values())}
            )
            style_chart = (
                alt.Chart(style_df)
                .mark_arc(innerRadius=55)
                .encode(
                    theta="queries:Q",
                    color=alt.Color("style:N", scale=alt.Scale(scheme="set2")),
                    tooltip=["style", "queries"],
                )
                .properties(height=230, title="Question-style mix")
            )
            st.altair_chart(style_chart, use_container_width=True)

    st.divider()

# ---- chart 1: overall metrics by config ------------------------------------

st.subheader("Overall metrics by retriever config")
st.caption(
    "Higher is better. The oracle configs pass the gold `document_type` as a filter — "
    "they represent the upper bound for a perfect classifier. MCP configs use "
    "`gpt-4o-mini` tool-calling to predict the filter."
)

if not overall.empty:
    metric_options = [
        c for c in ["hit@1", "hit@3", "hit@5", "hit@10", "adv_hit@5", "adv_hit@10", "mrr", "ndcg@10"]
        if c in overall.columns
    ]
    picked = st.multiselect(
        "Metrics",
        metric_options,
        default=[m for m in ["hit@1", "hit@5", "hit@10", "mrr", "ndcg@10"] if m in metric_options],
    )
    if picked:
        long = (
            overall[picked]
            .reset_index()
            .rename(columns={"_index": "config"})
            .melt(id_vars="config", var_name="metric", value_name="score")
        )
        bar = (
            alt.Chart(long)
            .mark_bar()
            .encode(
                x=alt.X("metric:N", title=None),
                y=alt.Y("score:Q", scale=alt.Scale(domain=[0, 1]), title="score"),
                color=alt.Color("config:N", scale=alt.Scale(scheme="tableau20")),
                xOffset="config:N",
                tooltip=["config", "metric", alt.Tooltip("score:Q", format=".3f")],
            )
            .properties(height=420)
        )
        st.altair_chart(bar, use_container_width=True)

    with st.expander("Raw table"):
        st.dataframe(overall.style.format("{:.3f}"), use_container_width=True)
else:
    st.warning("Could not parse the overall-metrics table from the report.")

st.divider()

# ---- chart 2: per doc_type heatmap -----------------------------------------

st.subheader("hit@5 by document_type × retriever")
st.caption(
    "Per-type breakdown surfaces regressions that the aggregate hides — e.g. "
    "MAR queries are systematically harder than JOINT_CSA under all configs."
)

per_dt = report.get("per_doctype_hit5", pd.DataFrame())
if not per_dt.empty:
    hm = (
        per_dt.reset_index()
        .rename(columns={"_index": "document_type"})
        .melt(id_vars="document_type", var_name="config", value_name="hit@5")
    )
    heat = (
        alt.Chart(hm)
        .mark_rect()
        .encode(
            x=alt.X("config:N", title=None, axis=alt.Axis(labelAngle=-30)),
            y=alt.Y("document_type:N", title=None),
            color=alt.Color(
                "hit@5:Q",
                scale=alt.Scale(scheme="yellowgreenblue", domain=[0, 1]),
                legend=alt.Legend(title="hit@5"),
            ),
            tooltip=["document_type", "config", alt.Tooltip("hit@5:Q", format=".3f")],
        )
        .properties(height=320)
    )
    text = (
        alt.Chart(hm)
        .mark_text(baseline="middle", fontSize=11)
        .encode(
            x="config:N",
            y="document_type:N",
            text=alt.Text("hit@5:Q", format=".2f"),
            color=alt.condition("datum['hit@5'] > 0.6", alt.value("white"), alt.value("black")),
        )
    )
    st.altair_chart(heat + text, use_container_width=True)

    with st.expander("Raw table"):
        st.dataframe(per_dt.style.format("{:.3f}"), use_container_width=True)
else:
    st.warning("Could not parse the per-doc_type table from the report.")

st.divider()

# ---- chart 3: alpha sweep --------------------------------------------------

st.subheader("Hybrid alpha sweep")
st.caption(
    "`alpha = 0` → BM25-only, `alpha = 1` → vector-only. "
    "Grid-searching alpha against the golden set is the retrieval analog of "
    "prompt-version tuning."
)

sweep = report.get("alpha_sweep", pd.DataFrame())
if not sweep.empty:
    sweep_reset = sweep.reset_index().rename(columns={"_index": "alpha"})
    sweep_reset["alpha"] = pd.to_numeric(sweep_reset["alpha"], errors="coerce")
    sweep_long = sweep_reset.melt(id_vars="alpha", var_name="metric", value_name="score")
    line = (
        alt.Chart(sweep_long)
        .mark_line(point=True, strokeWidth=2)
        .encode(
            x=alt.X("alpha:Q", title="alpha (0 = BM25, 1 = vector)"),
            y=alt.Y("score:Q", scale=alt.Scale(domain=[0.4, 1.0])),
            color=alt.Color("metric:N", scale=alt.Scale(scheme="category10")),
            tooltip=["metric", alt.Tooltip("alpha:Q", format=".2f"), alt.Tooltip("score:Q", format=".3f")],
        )
        .properties(height=380)
    )
    rule = (
        alt.Chart(pd.DataFrame({"alpha": [float(best_alpha)] if best_alpha else []}))
        .mark_rule(strokeDash=[5, 5], color="#888")
        .encode(x="alpha:Q")
    )
    st.altair_chart(line + rule, use_container_width=True)

    with st.expander("Raw table"):
        st.dataframe(sweep.style.format("{:.3f}"), use_container_width=True)
else:
    st.warning("Could not parse the alpha-sweep table from the report.")

st.divider()

# ---- chart 4: classifier agreement -----------------------------------------

st.subheader("Classifier (MCP simulation) agreement")
st.caption(
    "Gap between `hybrid@X+doctype_mcp` and `hybrid@X+doctype_oracle` rows above "
    "= the cost of classifier imperfection. The per-type breakdown shows which "
    "document types the LLM most often misrouted."
)

c1, c2, c3 = st.columns(3)
tc_agree = re.search(r"Tool-call agreement.*?\*\*([\d.]+)\*\*", md)
coverage = re.search(r"Coverage.*?\*\*([\d.]+)\*\*", md)
avg_types = re.search(r"Avg doc_types returned / query:\s*\*\*([\d.]+)\*\*", md)
c1.metric("Tool-call agreement", tc_agree.group(1) if tc_agree else "—")
c2.metric("Coverage (non-empty)", coverage.group(1) if coverage else "—")
c3.metric("Avg doc_types / query", avg_types.group(1) if avg_types else "—")

clf_gold = report.get("classifier_gold", pd.DataFrame())
if not clf_gold.empty and "mean" in clf_gold.columns:
    clf_reset = clf_gold.reset_index().rename(columns={"_index": "doc_type"})
    clf_chart = (
        alt.Chart(clf_reset)
        .mark_bar()
        .encode(
            x=alt.X("mean:Q", scale=alt.Scale(domain=[0, 1]), title="agreement (gold ∈ predicted)"),
            y=alt.Y("doc_type:N", sort="-x", title=None),
            color=alt.Color(
                "mean:Q", scale=alt.Scale(scheme="redyellowgreen", domain=[0, 1]), legend=None
            ),
            tooltip=["doc_type", alt.Tooltip("mean:Q", format=".3f"), "count"],
        )
        .properties(height=260)
    )
    text = (
        alt.Chart(clf_reset)
        .mark_text(align="left", dx=3, baseline="middle", fontSize=11)
        .encode(x="mean:Q", y=alt.Y("doc_type:N", sort="-x"), text=alt.Text("mean:Q", format=".3f"))
    )
    st.altair_chart(clf_chart + text, use_container_width=True)
    with st.expander("Raw table"):
        st.dataframe(clf_gold, use_container_width=True)

st.divider()

# ---- failures --------------------------------------------------------------

st.subheader(f"Failure cases (hit@10 = 0, config = `{best_cfg or '?'}`)")
fails = _failure_lines(md)
if fails:
    for line in fails:
        # Lines look like: "[JOINT_CSA] What type of files are listed ..."
        m = re.match(r"\[([^\]]+)\]\s*(.*)", line)
        if m:
            dtype, text = m.group(1), m.group(2)
            st.markdown(f"- **`{dtype}`** — {text}")
        else:
            st.markdown(f"- {line}")
else:
    st.caption("No failure lines in the report.")

st.divider()

# ---- golden-set explorer ---------------------------------------------------

st.subheader("Golden-set explorer")
if not golden.empty:
    filter_cols = st.columns(3)
    dtype_sel = filter_cols[0].multiselect(
        "document_type",
        sorted(golden["document_type"].unique()),
        default=sorted(golden["document_type"].unique()),
    )
    if "style_requested" in golden.columns:
        style_sel = filter_cols[1].multiselect(
            "style",
            sorted(golden["style_requested"].dropna().unique()),
            default=sorted(golden["style_requested"].dropna().unique()),
        )
    else:
        style_sel = None
    search = filter_cols[2].text_input("search query text", "")

    filt = golden[golden["document_type"].isin(dtype_sel)]
    if style_sel is not None:
        filt = filt[filt["style_requested"].isin(style_sel)]
    if search.strip():
        filt = filt[filt["query"].str.contains(search.strip(), case=False, na=False)]

    st.caption(f"{len(filt)} of {len(golden)} queries")
    show_cols = [
        c
        for c in [
            "query",
            "document_type",
            "expected_advisory_id",
            "expected_section",
            "style_requested",
            "source_token_count",
        ]
        if c in filt.columns
    ]
    st.dataframe(filt[show_cols], use_container_width=True, hide_index=True)
else:
    st.caption("`golden.jsonl` not found.")

st.divider()

with st.expander("Full raw report (markdown)"):
    st.markdown(md)
