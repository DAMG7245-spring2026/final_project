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
from datetime import date, datetime, timezone

import structlog
from pydantic import BaseModel

from app.services.llm_router import LLMTask, get_llm_router
from app.services.rag_router import get_rag_router_service
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
SYNTHESIS_MAX_TOKENS = 4000
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
Follow with a 3-5 sentence narrative paragraph that:
- Characterises the week's activity level relative to the numbers
  (e.g. "elevated KEV churn", "quiet week outside of X").
- Calls out any cross-CVE pattern visible in the top / newly-added
  lists (shared vendor, shared exploitation vector, same actor, same
  ransomware campaign, CISA Emergency Directive in play, etc.).
- Ends with the one headline a CISO would want on a Monday-morning
  executive summary email.

## This week's newly exploited
Iterate over every CVE in the "## Newly added KEV this week" input
block, **in the same order**, and write **one paragraph per CVE** (no
merging two different CVE IDs into a single paragraph, even if they
share vendor or advisory — separate paragraphs). Each paragraph is
4-7 sentences:
- Bold the CVE ID on first mention.
- Lead with vendor / product and kev_date_added. State the vulnerability
  class in plain English (e.g. "authentication bypass", "path traversal
  leading to RCE").
- Name threat actors, ransomware gangs, malware families, or campaigns
  **whenever the RAG evidence provides them**. Cite advisory IDs in
  parentheses the way the evidence does (e.g. "per `aa23-131a`").
- If kev_ransomware_use = 'Known', say so explicitly and link to the
  named ransomware group if evidence provides one.
- Include at least one concrete detection signal or IoC from the
  evidence when available (a process-tree observation, suspicious
  domain / IP / email, a Suricata signature hint, an EDR rule).
- Close with an actionable mitigation hint grounded in
  kev_required_action plus evidence detail (patch version, port to
  block, MFA requirement, workaround). "Apply patches" alone is not
  acceptable — tie it to what the advisory actually recommends.
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
  of 3-5 sentences (shorter than newly-exploited, but never a one-liner
  and never merge two CVE IDs into one paragraph):
  * Bold the CVE ID.
  * State cvss_score, kev_date_added, and ransomware status up front.
  * Include at least one evidence-grounded specific: a named actor /
    campaign if RAG evidence has one, or a concrete exploitation
    technique if it does not (e.g. "privilege escalation via PIE binary
    address allocation flaw").
  * Cite any advisory ID(s) the evidence references.
  * End with one mitigation or detection pointer.

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


def build_question(cve: WeeklyCve) -> str:
    """Build the RAG question for one CVE.

    Template with structured metadata injection. No LLM call — deterministic
    and free. Injects vendor / product / KEV / ransomware hints so
    ``text2cypher`` (entity anchoring) and ``hybrid_search`` (BM25 terms)
    get strong signal.
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


# ---- evidence pack --------------------------------------------------------


class CveEvidence(BaseModel):
    """Per-CVE evidence produced by one RAG worker."""

    cve: WeeklyCve
    question: str
    rag_answer: str
    graph_row_count: int = 0
    chunk_count: int = 0
    route: str = RAG_FORCE_ROUTE
    route_reasoning: str | None = None
    fallback_triggered: bool = False


# ---- worker ---------------------------------------------------------------


def _invoke_rag(cve: WeeklyCve) -> CveEvidence:
    """Sync worker — one RAG call per CVE, always via `force_route='both'`.

    Wrapped with ``asyncio.to_thread`` by the caller so the event loop
    stays unblocked. Runs synchronously to avoid rewriting the whole RAG
    stack as async.
    """
    rag = get_rag_router_service()
    question = build_question(cve)
    result = rag.answer(
        question=question,
        force_route=RAG_FORCE_ROUTE,
    )
    return CveEvidence(
        cve=cve,
        question=question,
        rag_answer=(result.get("answer") or "").strip(),
        graph_row_count=int(result.get("graph_row_count") or 0),
        chunk_count=len(result.get("chunks") or []),
        route=str(result.get("route") or RAG_FORCE_ROUTE),
        route_reasoning=result.get("route_reasoning"),
        fallback_triggered=bool(result.get("fallback_triggered") or False),
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
