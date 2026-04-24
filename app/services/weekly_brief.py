"""Orchestrator for the weekly CVE threat-intel brief.

Pipeline (orchestrator-workers pattern, per the Anthropic agent guide):

  1. `weekly_digest()` — pure SQL tier-ranking from ``cve_records``.
  2. Fan out one ``rag_router.answer(force_route='both')`` per unique CVE,
     bounded by ``asyncio.Semaphore(MAX_CONCURRENT_WORKERS)``. Each worker
     returns a ``CveEvidence`` pack (LLM-synthesised paragraph + raw graph
     rows + ranked advisory chunk counts).
  3. One synthesis LLM call stitches the summary + per-CVE evidence into a
     markdown brief matching the three hard-coded section template.

Deliberately simple: no evaluator-optimizer loop, no structured per-CVE
extraction, no evidence cache. All three are easy to bolt on later when
quality complaints surface — starting with the cheapest thing that works
matches the guidance in that article.

Concurrency note: ``rag_router.answer`` is synchronous and drives
``Text2CypherService`` + ``hybrid_search`` internally; we wrap each worker in
``asyncio.to_thread`` so the FastAPI event loop stays unblocked. The inner
``rag_router`` already fans graph/text in parallel with a 2-worker thread
pool, so peak thread count is ``MAX_CONCURRENT_WORKERS * 2``.

Question generation follows "option D" from the design discussion: a
template with structured metadata injection (vendor/product/ransomware/KEV
date). Zero extra LLM calls; deterministic output; strong BM25 + text2cypher
entity hints. If quality ever demands per-CVE tailoring we can swap in an
LLM-generated question without touching the fan-out or synthesis layers.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from typing import AsyncIterator, Iterator

import structlog
from pydantic import BaseModel

from app.services.hybrid_search import hybrid_search
from app.services.llm_router import LLMTask, get_llm_router
from app.services.text2cypher import get_text2cypher_service
from app.services.weekly_digest import (
    DEFAULT_MAX_TIER,
    DEFAULT_NEWLY_ADDED_KEV_N,
    DEFAULT_TOP_N,
    WeeklyCve,
    WeeklyDigestSummary,
    weekly_digest,
)

log = structlog.get_logger(__name__)


MAX_CONCURRENT_WORKERS = 8
RAG_FORCE_ROUTE = "both"  # always run graph + text for the CVE full-picture query
SYNTHESIS_MAX_TOKENS = 8000
SYNTHESIS_TEMPERATURE = 0.2  # a touch of variance for prose; numbers are grounded by the evidence pack


SYNTHESIS_SYSTEM_PROMPT = """You are a CISO threat-intelligence writer producing a weekly brief.

Input: a structured block containing (1) summary counts for the week,
(2) top CVEs ordered by threat tier, and (3) CVEs newly added to the CISA
KEV catalog this week. Each CVE block includes structured fields followed
by a RAG-synthesised evidence paragraph drawn from the CTI knowledge graph
and advisory corpus. The RAG evidence often contains **named threat
actors**, **ransomware gang names**, **malware / C2 families**, **campaigns**,
**advisory IDs** (e.g. `aa23-131a`), **CVSS detail**, and **IoCs**
(domains, IPs, emails). Your job is to mine those specifics and surface
them in the brief — a CISO will not accept "a threat actor exploited
this" when the evidence names the group.

Output: GitHub-flavoured markdown with exactly three sections, in this
order and with these exact headings:

## Headline numbers
A small markdown table of the six counts (total_modified, newly_published,
critical_count, kev_added_count, kev_ransomware_count, has_exploit_ref_count).
Follow with a 5-8 sentence narrative paragraph that:
- Characterises the week's activity level relative to the numbers
  (e.g. "elevated KEV churn", "quiet week outside of X").
- Names the dominant vendors / products of the week and how many CVEs
  each contributed to the top / newly-added lists.
- Calls out every cross-CVE pattern visible in the top / newly-added
  lists (shared vendor, shared exploitation vector, same actor, same
  ransomware campaign, CISA Emergency Directive in play, etc.) — if
  multiple patterns exist, mention each one briefly.
- Surfaces any recurring threat actor, ransomware gang, or malware
  family that appears across **two or more** CVE evidence blocks.
- Ends with the one headline a CISO would want on a Monday-morning
  executive summary email.

## This week's newly exploited
Iterate over every CVE in the "## Newly added KEV this week" input
block, **in the same order**, and write **one paragraph per CVE** (no
merging two different CVE IDs into a single paragraph, even if they
share vendor or advisory — separate paragraphs). Each paragraph is
6-10 sentences:
- Bold the CVE ID on first mention.
- Lead with vendor / product and kev_date_added. State the vulnerability
  class in plain English (e.g. "authentication bypass", "path traversal
  leading to RCE") and include the CVSS vector breakdown (attack vector,
  privileges required, user interaction, scope, CIA impact) when the
  structured fields or evidence provide it.
- List **every** named threat actor, ransomware gang, malware family,
  C2 framework, and campaign the RAG evidence mentions — do not
  cherry-pick one when several are present. Cite **all** advisory IDs
  the evidence references in parentheses (e.g. "per `aa23-131a`,
  `aa24-060a`"), not just the first one.
- If kev_ransomware_use = 'Known', say so explicitly and link to every
  named ransomware group, affiliate, or RaaS operator the evidence
  provides. If the evidence ties the CVE to a specific ransomware
  campaign timeline (initial access, mass exploitation window), include
  those dates.
- Include **at least two distinct** detection signals or IoCs from the
  evidence when available: process-tree observations, suspicious
  domains / IPs / emails, Suricata / YARA / Sigma rule hints, EDR rules,
  file hashes, log-line patterns, or network-traffic signatures. Group
  them by type (e.g. "Network: ...; Host: ...").
- Close with **two or more** actionable mitigation or hardening steps
  grounded in kev_required_action plus evidence detail (specific patch
  version / KB, port or protocol to block, MFA or segmentation
  requirement, configuration hardening, compensating control, WAF rule).
  "Apply patches" alone is not acceptable — tie each step to what the
  advisory or evidence actually recommends.
- If the same CVE ID is also in ``overlap_ids`` (shown in the input
  header), merge both the newly-added and Tier-1 angles into this one
  paragraph and note the dual significance. That CVE will then be
  skipped in the Most Dangerous section below.

## Most dangerous active threats
Iterate over every CVE in the "## Top CVEs (danger-ranked)" input block,
**in the same order as the input**. For each top CVE:
- If its CVE ID **is in ``overlap_ids``** (shown in the input header),
  **SKIP it** — it has already been covered in the newly-exploited
  section above. Do not restate.
- If its CVE ID is **NOT in ``overlap_ids``**, write **one paragraph**
  of 5-8 sentences (never a one-liner, and never merge two CVE IDs
  into one paragraph):
  * Bold the CVE ID.
  * State cvss_score, exploitability_score, impact_score, kev_date_added,
    and ransomware status up front. Briefly explain what the score
    combination implies (e.g. "high impact but low exploitability —
    urgent patch window, limited mass-exploitation risk").
  * List **every** named actor, campaign, malware family, or C2 framework
    the RAG evidence provides. When the evidence has none, describe the
    concrete exploitation technique in detail (root cause, primitive
    gained, prerequisites) — e.g. "privilege escalation via PIE binary
    address allocation flaw enabling arbitrary RIP control".
  * Cite **every** advisory ID the evidence references, not just one.
  * Include at least one concrete IoC or detection signal when the
    evidence provides it.
  * End with **at least two** mitigation or detection pointers grounded
    in the evidence (patch version, configuration hardening, network
    control, detection rule) — not generic "apply patches" advice.

A top CVE must appear in **exactly one** of the two CVE sections — in
newly-exploited if it is in ``overlap_ids``, otherwise here. **Never
drop a top CVE**; a reader audits by checking that every CVE ID listed
in the "## Top CVEs" input block appears in either section.

Fallback: only if **every** CVE in the Top CVEs input block is in
``overlap_ids`` (i.e. the entire top list was absorbed into
newly-exploited), replace this section's body with a single line:
"All Tier-1 CVEs this week are covered in the newly-exploited section
above." Do not use this fallback when even one top CVE is missing from
``overlap_ids``.

Hard rules:
- Cite CVE IDs verbatim; never invent, abbreviate, or modify them.
- Use numbers from the input exactly — do not round, estimate, or invent.
- Use ISO date format (YYYY-MM-DD) when citing dates.
- Never fabricate threat-actor names, campaign names, advisory IDs, or
  IoCs. If the RAG evidence doesn't name one, say "no named actor in
  available advisories" rather than guessing.
- Write for a CISO audience: concrete, actionable, no filler, no
  "In conclusion" or "Executive summary" wrappers.
- Output only the three sections. No preamble, no epilogue, no code
  fences wrapping the whole brief.
"""


# ---- per-CVE question template (option D) ---------------------------------


def build_text_question(cve: WeeklyCve) -> str:
    """Question for the advisory-corpus retriever (BM25 + vector).

    Template with structured metadata injection. No LLM call — deterministic
    and free. Injects vendor / product / KEV / ransomware hints so
    ``hybrid_search`` (BM25 terms + vector similarity) gets strong signal.
    Mentions detection / mitigation / advisories freely — that's what the
    advisory corpus contains.
    """
    vendor = cve.kev_vendor_project or "unknown vendor"
    product = cve.kev_product or "the affected product"
    ransomware_hint = (
        "This CVE is linked to known ransomware campaigns. "
        if cve.kev_ransomware_use == "Known"
        else ""
    )
    kev_hint = (
        f"It was added to the CISA KEV catalog on {cve.kev_date_added}. "
        if cve.is_kev and cve.kev_date_added
        else ""
    )
    return (
        f"{cve.cve_id} affects {vendor} {product}. "
        f"{ransomware_hint}{kev_hint}"
        "What threat actors, malware families, and campaigns have exploited "
        "this vulnerability? Include detection indicators and mitigation "
        "guidance from available advisories."
    )


def build_graph_question(cve: WeeklyCve) -> str:
    """Question for the graph retriever (text2cypher).

    Deliberately narrow: the graph schema has no advisory / detection /
    mitigation nodes. Mentioning those terms makes text2cypher's LLM
    classifier reject the question (``can_answer=false``). We ask only
    about actors / malware / campaigns — the nodes that actually exist —
    and name the product explicitly so the generated Cypher can UNION
    a product-anchored ``USES|TARGETS`` path with the direct CVE
    ``EXPLOITS`` path.
    """
    vendor = cve.kev_vendor_project or ""
    product = cve.kev_product or ""
    vp = (vendor + " " + product).strip() or "the affected product"
    return (
        f"Which threat actors, malware families, and campaigns are known to "
        f"exploit {cve.cve_id}, or to use or target {vp}?"
    )


# ---- evidence pack --------------------------------------------------------


class CveEvidence(BaseModel):
    """Per-CVE evidence produced by one RAG worker."""

    cve: WeeklyCve
    question: str
    rag_answer: str
    graph_answer: str | None = None
    text_answer: str | None = None
    graph_cypher: str | None = None
    graph_row_count: int = 0
    chunk_count: int = 0
    advisory_ids: list[str] = []
    route: str = RAG_FORCE_ROUTE
    route_reasoning: str | None = None
    fallback_triggered: bool = False
    # LLM usage from text2cypher (cypher generation + answer generation).
    # hybrid_search has no LLM so text-retrieval contributes 0.
    graph_prompt_tokens: int = 0
    graph_completion_tokens: int = 0
    graph_cost_usd: float = 0.0
    graph_llm_calls: int = 0


# ---- worker ---------------------------------------------------------------


def _merge_answers(graph_answer: str | None, chunks: list[dict]) -> str:
    """Stitch the text2cypher paragraph and the raw advisory chunks into a
    labeled block. The synthesis prompt consumes ``rag_answer`` verbatim;
    section headers keep graph vs. text provenance visible to the LLM.

    Graph "no data found" templates are dropped so empty-graph weeks don't
    pollute the prompt with boilerplate.
    """
    parts: list[str] = []
    if graph_answer and "no matching data" not in graph_answer.lower():
        parts.append("## Graph evidence\n" + graph_answer.strip())
    if chunks:
        chunk_texts = [
            f"[{c.get('advisory_id', '?')} §{c.get('section_name') or '-'}] "
            f"{c.get('chunk_text', '')}"
            for c in chunks[:10]
        ]
        parts.append("## Advisory passages\n" + "\n\n".join(chunk_texts))
    return "\n\n".join(parts) or "(no evidence returned)"


def _invoke_rag(cve: WeeklyCve) -> CveEvidence:
    """Sync worker — one graph call + one text call per CVE, run in parallel.

    Wrapped with ``asyncio.to_thread`` by the caller so the event loop
    stays unblocked. Bypasses ``rag_router`` so we can feed each retriever
    a question tailored to its capabilities (see ``build_graph_question``
    vs. ``build_text_question``).
    """
    text2cypher = get_text2cypher_service()
    graph_q = build_graph_question(cve)
    text_q = build_text_question(cve)

    with ThreadPoolExecutor(max_workers=2) as pool:
        graph_fut = pool.submit(text2cypher.query, graph_q)
        # No metadata filter: rely on BM25 + vector text match against the
        # CVE id / vendor / product terms already baked into text_q.
        # Pre-filtering by cve_ids was returning 0 chunks for all three CVEs
        # this week — the advisory_chunks.cve_ids column isn't populated
        # consistently enough to use as a hard filter.
        text_fut = pool.submit(
            hybrid_search,
            query=text_q,
            top_k=10,
        )
        graph = graph_fut.result()
        chunks = text_fut.result()

    graph_answer = graph.get("answer")
    merged = _merge_answers(graph_answer, chunks)
    seen_adv: dict[str, None] = {}
    for c in chunks:
        aid = c.get("advisory_id")
        if aid and aid not in seen_adv:
            seen_adv[aid] = None
    g_usage = graph.get("usage") or {}
    return CveEvidence(
        cve=cve,
        question=f"[graph] {graph_q}\n[text] {text_q}",
        rag_answer=merged,
        graph_answer=graph_answer,
        text_answer=None,
        graph_cypher=graph.get("cypher"),
        graph_row_count=int(graph.get("row_count") or 0),
        chunk_count=len(chunks),
        advisory_ids=list(seen_adv.keys()),
        route="both",
        route_reasoning="bypassed rag_router — split graph/text questions",
        fallback_triggered=False,
        graph_prompt_tokens=int(g_usage.get("prompt_tokens") or 0),
        graph_completion_tokens=int(g_usage.get("completion_tokens") or 0),
        graph_cost_usd=float(g_usage.get("cost_usd") or 0.0),
        graph_llm_calls=int(g_usage.get("call_count") or 0),
    )


async def _gather_cve_evidence(cves: list[WeeklyCve]) -> list[CveEvidence]:
    """Fan-out RAG workers. Bounded concurrency via ``Semaphore``.

    Dedup is first-seen-wins so a CVE appearing in both top_cves and
    newly_added_kev only triggers one RAG call — the synthesis prompt
    resolves the duplication at write time.
    """
    seen: dict[str, WeeklyCve] = {}
    for c in cves:
        seen.setdefault(c.cve_id, c)
    unique = list(seen.values())

    if not unique:
        return []

    sem = asyncio.Semaphore(MAX_CONCURRENT_WORKERS)

    async def _bounded(cve: WeeklyCve) -> CveEvidence:
        async with sem:
            return await asyncio.to_thread(_invoke_rag, cve)

    log.info(
        "weekly_brief_fanout_start",
        unique_cves=len(unique),
        max_workers=MAX_CONCURRENT_WORKERS,
    )
    results = await asyncio.gather(*(_bounded(c) for c in unique))
    log.info(
        "weekly_brief_fanout_done",
        unique_cves=len(unique),
        graph_rows_total=sum(r.graph_row_count for r in results),
        chunks_total=sum(r.chunk_count for r in results),
    )
    return list(results)


# ---- synthesis ------------------------------------------------------------


def _format_cve_block(ev: CveEvidence) -> str:
    """One block of structured + narrative evidence for the synthesis prompt."""
    cve = ev.cve
    return (
        f"### {cve.cve_id}\n"
        f"- Tier: {cve.tier} ({cve.tier_reason})\n"
        f"- Vendor / product: {cve.kev_vendor_project or 'n/a'} / "
        f"{cve.kev_product or 'n/a'}\n"
        f"- CVSS: {cve.cvss_score} ({cve.cvss_severity}) | "
        f"exploitability {cve.exploitability_score} | "
        f"impact {cve.impact_score}\n"
        f"- Confidentiality / integrity impact: "
        f"{cve.confidentiality_impact} / {cve.integrity_impact}\n"
        f"- is_kev: {cve.is_kev} | ransomware_use: {cve.kev_ransomware_use} | "
        f"kev_date_added: {cve.kev_date_added} | "
        f"kev_due_date: {cve.kev_due_date}\n"
        f"- has_exploit_ref: {cve.has_exploit_ref}\n"
        f"- published_date: {cve.published_date}\n"
        f"- NVD description: {cve.description_en or 'n/a'}\n"
        f"- kev_required_action: {cve.kev_required_action or 'n/a'}\n\n"
        f"RAG evidence (graph_rows={ev.graph_row_count}, "
        f"chunks={ev.chunk_count}):\n"
        f"{ev.rag_answer or '(no evidence returned)'}\n"
    )


def _synthesize_brief(
    summary: WeeklyDigestSummary,
    top_cves: list[WeeklyCve],
    newly_added_kev: list[WeeklyCve],
    evidence: list[CveEvidence],
) -> tuple[str, int, int, float]:
    """Single LLM call that stitches everything into the three-section brief.

    Returns ``(markdown, prompt_tokens, completion_tokens, cost_usd)`` so
    callers can surface cost/usage without digging into the LLMRouter
    record shape.
    """
    router = get_llm_router()

    ev_by_cve = {e.cve.cve_id: e for e in evidence}
    top_blocks = [
        _format_cve_block(ev_by_cve[c.cve_id])
        for c in top_cves
        if c.cve_id in ev_by_cve
    ]
    newly_blocks = [
        _format_cve_block(ev_by_cve[c.cve_id])
        for c in newly_added_kev
        if c.cve_id in ev_by_cve
    ]
    overlap_ids = {c.cve_id for c in top_cves} & {c.cve_id for c in newly_added_kev}

    user_content = (
        f"Window: {summary.window_start} to {summary.window_end} (half-open).\n"
        f"Overlap between top-danger and newly-added-KEV sections: "
        f"{sorted(overlap_ids) or 'none'}\n\n"
        "## Summary counts\n"
        f"- total_modified: {summary.total_modified}\n"
        f"- newly_published: {summary.newly_published}\n"
        f"- critical_count: {summary.critical_count}\n"
        f"- kev_added_count: {summary.kev_added_count}\n"
        f"- kev_ransomware_count: {summary.kev_ransomware_count}\n"
        f"- has_exploit_ref_count: {summary.has_exploit_ref_count}\n\n"
        "## Top CVEs (danger-ranked)\n\n"
        + ("\n".join(top_blocks) or "(no rows)\n")
        + "\n## Newly added KEV this week\n\n"
        + ("\n".join(newly_blocks) or "(no rows)\n")
    )

    record = router.complete(
        task=LLMTask.ANSWER_GENERATION,
        messages=[
            {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        temperature=SYNTHESIS_TEMPERATURE,
        max_tokens=SYNTHESIS_MAX_TOKENS,
        extra_log={
            "stage": "weekly_brief_synthesis",
            "n_top": len(top_cves),
            "n_newly": len(newly_added_kev),
            "n_evidence": len(evidence),
            "n_overlap": len(overlap_ids),
        },
    )
    content = (record.response.choices[0].message.content or "").strip()
    return (
        content,
        record.prompt_tokens,
        record.completion_tokens,
        record.cost_usd,
    )


def _build_synthesis_messages(
    summary: WeeklyDigestSummary,
    top_cves: list[WeeklyCve],
    newly_added_kev: list[WeeklyCve],
    evidence: list[CveEvidence],
) -> list[dict[str, str]]:
    """Shared prompt builder used by both the sync and streaming synthesis paths."""
    ev_by_cve = {e.cve.cve_id: e for e in evidence}
    top_blocks = [
        _format_cve_block(ev_by_cve[c.cve_id])
        for c in top_cves
        if c.cve_id in ev_by_cve
    ]
    newly_blocks = [
        _format_cve_block(ev_by_cve[c.cve_id])
        for c in newly_added_kev
        if c.cve_id in ev_by_cve
    ]
    overlap_ids = {c.cve_id for c in top_cves} & {c.cve_id for c in newly_added_kev}

    user_content = (
        f"Window: {summary.window_start} to {summary.window_end} (half-open).\n"
        f"Overlap between top-danger and newly-added-KEV sections: "
        f"{sorted(overlap_ids) or 'none'}\n\n"
        "## Summary counts\n"
        f"- total_modified: {summary.total_modified}\n"
        f"- newly_published: {summary.newly_published}\n"
        f"- critical_count: {summary.critical_count}\n"
        f"- kev_added_count: {summary.kev_added_count}\n"
        f"- kev_ransomware_count: {summary.kev_ransomware_count}\n"
        f"- has_exploit_ref_count: {summary.has_exploit_ref_count}\n\n"
        "## Top CVEs (danger-ranked)\n\n"
        + ("\n".join(top_blocks) or "(no rows)\n")
        + "\n## Newly added KEV this week\n\n"
        + ("\n".join(newly_blocks) or "(no rows)\n")
    )
    return [
        {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def _stream_synthesize_brief(
    summary: WeeklyDigestSummary,
    top_cves: list[WeeklyCve],
    newly_added_kev: list[WeeklyCve],
    evidence: list[CveEvidence],
    usage_sink: dict | None = None,
) -> Iterator[str]:
    """Token-streaming synthesis. Yields markdown deltas; cost is logged
    by ``LLMRouter.stream_complete`` when the stream finishes. Optional
    ``usage_sink`` is populated with prompt/completion tokens, cost_usd,
    and daily_spend/budget after the stream ends."""
    router = get_llm_router()
    overlap_ids = {c.cve_id for c in top_cves} & {c.cve_id for c in newly_added_kev}
    yield from router.stream_complete(
        task=LLMTask.ANSWER_GENERATION,
        messages=_build_synthesis_messages(summary, top_cves, newly_added_kev, evidence),
        temperature=SYNTHESIS_TEMPERATURE,
        max_tokens=SYNTHESIS_MAX_TOKENS,
        extra_log={
            "stage": "weekly_brief_synthesis_stream",
            "n_top": len(top_cves),
            "n_newly": len(newly_added_kev),
            "n_evidence": len(evidence),
            "n_overlap": len(overlap_ids),
        },
        usage_sink=usage_sink,
    )


# ---- public API -----------------------------------------------------------


class WeeklyBrief(BaseModel):
    """Output of the weekly brief pipeline.

    ``markdown`` is the final brief text. The rest is metadata for
    traceability / debugging: the digest snapshot the LLM saw, the
    per-CVE evidence packs, token/cost totals, and timestamps.
    """

    markdown: str
    generated_at: datetime
    window_start: date
    window_end: date
    summary: WeeklyDigestSummary
    top_cves: list[WeeklyCve]
    newly_added_kev: list[WeeklyCve]
    evidence: list[CveEvidence]
    worker_count: int
    synthesis_prompt_tokens: int
    synthesis_completion_tokens: int
    synthesis_cost_usd: float


async def generate_weekly_brief(
    *,
    window_start: date | None = None,
    window_end: date | None = None,
    limit: int = DEFAULT_TOP_N,
    max_tier: int = DEFAULT_MAX_TIER,
    newly_added_limit: int = DEFAULT_NEWLY_ADDED_KEV_N,
    ingested_after: datetime | None = None,
) -> WeeklyBrief:
    """Run the full digest → fan-out → synthesise pipeline.

    All three phases are async-safe: the SQL digest and synthesis LLM call
    are sync functions wrapped with ``asyncio.to_thread`` so they don't
    block the FastAPI event loop; the fan-out is ``asyncio.gather`` with
    bounded concurrency.
    """
    # 1. Digest (pure SQL; fast enough that offloading to the thread pool
    #    is cheap insurance against blocking the event loop under load).
    digest = await asyncio.to_thread(
        weekly_digest,
        window_start=window_start,
        window_end=window_end,
        limit=limit,
        max_tier=max_tier,
        newly_added_limit=newly_added_limit,
        ingested_after=ingested_after,
    )
    summary: WeeklyDigestSummary = digest["summary"]
    top: list[WeeklyCve] = digest["top_cves"]
    newly: list[WeeklyCve] = digest["newly_added_kev"]

    # 2. Fan out — one RAG call per unique CVE, concurrent and bounded.
    evidence = await _gather_cve_evidence(top + newly)

    # 3. Synthesise the markdown brief in one LLM call.
    markdown, p_tok, c_tok, cost = await asyncio.to_thread(
        _synthesize_brief, summary, top, newly, evidence
    )

    brief = WeeklyBrief(
        markdown=markdown,
        generated_at=datetime.now(timezone.utc),
        window_start=summary.window_start,
        window_end=summary.window_end,
        summary=summary,
        top_cves=top,
        newly_added_kev=newly,
        evidence=evidence,
        worker_count=len(evidence),
        synthesis_prompt_tokens=p_tok,
        synthesis_completion_tokens=c_tok,
        synthesis_cost_usd=cost,
    )
    log.info(
        "weekly_brief_generated",
        window_start=summary.window_start.isoformat(),
        window_end=summary.window_end.isoformat(),
        workers=brief.worker_count,
        markdown_chars=len(brief.markdown),
        synthesis_cost_usd=round(brief.synthesis_cost_usd, 6),
        synthesis_prompt_tokens=brief.synthesis_prompt_tokens,
        synthesis_completion_tokens=brief.synthesis_completion_tokens,
    )
    return brief


# ---- streaming (SSE) ------------------------------------------------------


async def stream_weekly_brief(
    *,
    window_start: date | None = None,
    window_end: date | None = None,
    limit: int = DEFAULT_TOP_N,
    max_tier: int = DEFAULT_MAX_TIER,
    newly_added_limit: int = DEFAULT_NEWLY_ADDED_KEV_N,
    ingested_after: datetime | None = None,
) -> AsyncIterator[tuple[str, str]]:
    """Yield ``(event_name, json_payload)`` tuples for the SSE endpoint.

    Event order:
      * ``meta``     — window + digest headline counts (as soon as SQL completes)
      * ``cves``     — top_cves, newly_added_kev, evidence (after RAG fan-out)
      * ``markdown`` — one event per LLM token delta (during synthesis)
      * ``done``     — generated_at + worker_count (final)

    The router wraps each tuple into ``event:/data:`` SSE frames.
    """
    import json

    # 1. Digest
    digest = await asyncio.to_thread(
        weekly_digest,
        window_start=window_start,
        window_end=window_end,
        limit=limit,
        max_tier=max_tier,
        newly_added_limit=newly_added_limit,
        ingested_after=ingested_after,
    )
    summary: WeeklyDigestSummary = digest["summary"]
    top: list[WeeklyCve] = digest["top_cves"]
    newly: list[WeeklyCve] = digest["newly_added_kev"]

    yield ("meta", summary.model_dump_json())

    # 2. Fan out RAG
    evidence = await _gather_cve_evidence(top + newly)

    cves_payload = {
        "top_cves": [c.model_dump(mode="json") for c in top],
        "newly_added_kev": [c.model_dump(mode="json") for c in newly],
        "evidence": [e.model_dump(mode="json") for e in evidence],
    }
    yield ("cves", json.dumps(cves_payload))

    # 3. Stream synthesis tokens. ``stream_complete`` is a sync generator —
    # pull chunks on a thread so the event loop stays free.
    usage_sink: dict = {}
    gen = _stream_synthesize_brief(summary, top, newly, evidence, usage_sink=usage_sink)
    total_chars = 0
    while True:
        delta = await asyncio.to_thread(next, gen, None)
        if delta is None:
            break
        total_chars += len(delta)
        yield ("markdown", json.dumps({"delta": delta}))

    # Aggregate totals across the whole workflow: every CVE worker's
    # text2cypher usage + the single synthesis call. hybrid_search has no
    # LLM so there's nothing to add from the text-retrieval path.
    fanout_prompt_tokens = sum(e.graph_prompt_tokens for e in evidence)
    fanout_completion_tokens = sum(e.graph_completion_tokens for e in evidence)
    fanout_cost_usd = sum(e.graph_cost_usd for e in evidence)
    fanout_llm_calls = sum(e.graph_llm_calls for e in evidence)

    synthesis_prompt_tokens = int(usage_sink.get("prompt_tokens") or 0)
    synthesis_completion_tokens = int(usage_sink.get("completion_tokens") or 0)
    synthesis_cost_usd = float(usage_sink.get("cost_usd") or 0.0)

    total_prompt_tokens = fanout_prompt_tokens + synthesis_prompt_tokens
    total_completion_tokens = fanout_completion_tokens + synthesis_completion_tokens
    total_cost_usd = fanout_cost_usd + synthesis_cost_usd
    total_llm_calls = fanout_llm_calls + (1 if synthesis_prompt_tokens else 0)

    yield (
        "done",
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "worker_count": len(evidence),
                "markdown_chars": total_chars,
                # Synthesis-only usage (last LLM call).
                "synthesis_prompt_tokens": synthesis_prompt_tokens,
                "synthesis_completion_tokens": synthesis_completion_tokens,
                "synthesis_cost_usd": synthesis_cost_usd,
                # Fan-out usage (sum across every per-CVE text2cypher call).
                "fanout_prompt_tokens": fanout_prompt_tokens,
                "fanout_completion_tokens": fanout_completion_tokens,
                "fanout_cost_usd": fanout_cost_usd,
                "fanout_llm_calls": fanout_llm_calls,
                # Workflow totals.
                "prompt_tokens_total": total_prompt_tokens,
                "completion_tokens_total": total_completion_tokens,
                "cost_usd_total": total_cost_usd,
                "llm_calls_total": total_llm_calls,
                # Daily budget state (read at synthesis-call completion).
                "daily_spend_usd": usage_sink.get("daily_spend_usd"),
                "daily_budget_usd": usage_sink.get("daily_budget_usd"),
            }
        ),
    )
    log.info(
        "weekly_brief_workflow_usage",
        window_start=summary.window_start.isoformat(),
        window_end=summary.window_end.isoformat(),
        prompt_tokens_total=total_prompt_tokens,
        completion_tokens_total=total_completion_tokens,
        cost_usd_total=round(total_cost_usd, 6),
        llm_calls_total=total_llm_calls,
    )
    log.info(
        "weekly_brief_stream_done",
        window_start=summary.window_start.isoformat(),
        window_end=summary.window_end.isoformat(),
        workers=len(evidence),
        markdown_chars=total_chars,
    )
