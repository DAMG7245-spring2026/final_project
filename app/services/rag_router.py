"""LLM-based RAG router in front of text2cypher + hybrid_search.

Picks one of three retrieval strategies per question:

  graph : structured-fact question naming specific entities → Text2CypherService.query
  text  : guidance/mitigation/detection/semantic question → hybrid_search (full corpus)
  both  : broad/complete question about an entity → run both in parallel and merge

The classifier is a single structured-output LLM call through
`LLMRouter.complete()` (Pydantic `response_format`) so it's budget-tracked
and logged consistently. The eval harness can bypass the classifier with
`force_route` and disable the graph→text zero-row fallback with
`disable_fallback` to measure each route in isolation.
"""

from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterator, Literal

import structlog
from pydantic import BaseModel, Field, ValidationError
from structlog.contextvars import bound_contextvars

from app.services.hybrid_search import hybrid_search
from app.services.llm_router import LLMTask, get_llm_router
from app.services.text2cypher import get_text2cypher_service

log = structlog.get_logger(__name__)

Route = Literal["graph", "text", "both"]

TEXT_ROUTE_TOP_K = 10

ROUTER_SYSTEM_PROMPT = """You are a retrieval router for a Cyber Threat Intelligence RAG system.

Pick exactly one retrieval route for the user's question and return it
using the structured-output schema {route, reasoning}. The three routes are:

- "graph": The question names specific entities (a threat actor, malware,
  CVE, campaign, technique) AND asks for a structured fact about them —
  who uses what, which CVEs, counts, relationships, attribution. A Cypher
  query over the CTI knowledge graph is the best answer source.
  Examples:
    * "Which CVEs does Volt Typhoon exploit?"
    * "What malware is attributed to APT41?"
    * "How many known-exploited CVEs are linked to any actor?"

- "text": The question is about guidance, mitigation, detection,
  best-practice, procedure, or summary — or it uses concepts without
  naming a specific graph entity. The answer lives in advisory prose,
  not in graph edges.
  Examples:
    * "What are CISA's recommended ransomware mitigations for small businesses?"
    * "How should defenders detect living-off-the-land techniques?"
    * "Summarize the latest MOVEit advisory."

- "both": A broad/complete question about a specific entity that wants
  structured facts AND narrative context (detection, mitigation, TTPs).
  Run graph and text in parallel and merge.
  Examples:
    * "Tell me everything about APT41, including detection guidance."
    * "Give me a full picture of Volt Typhoon — targets, tools, and how to defend."

Heuristics:
- Named entity + structured fact → graph
- No named entity OR asks for advice/mitigation/summary/detection → text
- Named entity AND asks for advice/detection/full picture → both

Always include a one-sentence `reasoning` explaining which heuristic fired."""


class RouteDecision(BaseModel):
    """Structured output for the route classifier.

    Using Pydantic `response_format` gives us a typed, validated decision
    without any markdown/tool-call unwrapping — mirrors the pattern used
    in text2cypher.CypherResponse.
    """

    route: Route = Field(
        description="Which retrieval strategy to use: graph, text, or both."
    )
    reasoning: str = Field(
        description="One sentence explaining why this route was picked."
    )


ANSWER_SYSTEM = """You are a cybersecurity analyst writing a threat intelligence answer.

You may receive evidence from two sources:
  1. Knowledge-graph rows (structured Neo4j results from a Cypher query)
  2. Advisory passages (ranked CISA advisory chunks from hybrid BM25+vector search)

Guidelines:
- Use bullet points to organize findings. Do not use markdown headers.
- Cite advisory IDs (e.g. aa22-011a) when a fact comes from an advisory passage.
- When graph rows are present, explain what each relationship means in a threat-intel context (impact, severity, common usage).
- When both sources are present, weave them: graph gives the skeleton, advisory passages give the narrative.
- If both sources are empty, say no matching data was found.
- Aim for 400-600 words."""


def _parse_route_response(record: Any) -> tuple[Route, str]:
    """Validate the structured-output JSON into a RouteDecision.

    Returns ("both", "parse_failed") on any malformed output — the safe default
    is slower but still answers the question.
    """
    content = getattr(record.response.choices[0].message, "content", None)
    if not content:
        log.warning("rag_router_empty_content")
        return "both", "parse_failed"
    try:
        parsed = RouteDecision.model_validate_json(content)
    except ValidationError as e:
        log.warning(
            "rag_router_schema_validation_failed",
            error=str(e),
            content_preview=content[:200],
        )
        return "both", "parse_failed"
    return parsed.route, parsed.reasoning


def choose_route(question: str) -> tuple[Route, str]:
    """Classify the question into one of ROUTE_ENUM via structured output.

    Returns (route, reasoning). The reasoning is surfaced in the endpoint
    response so the AI-as-judge eval harness can audit why the classifier
    picked a given route.
    """
    router = get_llm_router()
    try:
        record = router.complete(
            task=LLMTask.RAG_ROUTING,
            messages=[
                {"role": "system", "content": ROUTER_SYSTEM_PROMPT},
                {"role": "user", "content": question},
            ],
            response_format=RouteDecision,
            temperature=0,
            max_tokens=200,
            extra_log={"stage": "rag_routing"},
        )
    except Exception as e:
        log.exception("rag_router_llm_call_failed")
        return "both", f"llm_call_failed: {e}"
    return _parse_route_response(record)


class RAGRouterService:
    """Dispatches a question to graph / text / both and merges into one answer."""

    def __init__(self) -> None:
        self._llm = get_llm_router()
        self._text2cypher = get_text2cypher_service()

    # ---------- public API ----------

    def answer(
        self,
        question: str,
        force_route: Route | None = None,
        disable_fallback: bool = False,
    ) -> dict[str, Any]:
        request_id = uuid.uuid4().hex[:12]
        with bound_contextvars(
            request_id=request_id,
            question_preview=question[:160],
        ):
            log.info(
                "rag_router_start",
                force_route=force_route,
                disable_fallback=disable_fallback,
            )

            if force_route is not None:
                route: Route = force_route
                reasoning: str | None = None
                was_forced = True
            else:
                route, picked_reasoning = choose_route(question)
                reasoning = picked_reasoning
                was_forced = False
                log.info("rag_router_picked", route=route, reasoning=reasoning)

            result = self._dispatch(route, question)

            # Graph → text zero-row fallback. Defends against router
            # misclassification and KG ingestion lag. Off when the eval
            # harness wants to measure the chosen route standalone.
            fallback_triggered = False
            if (
                route == "graph"
                and not disable_fallback
                and (result.get("graph_row_count") or 0) == 0
            ):
                log.info("rag_router_graph_zero_fallback")
                text_result = self._dispatch("text", question)
                # Keep the original graph evidence (empty) visible so the
                # caller can see the fallback happened, but take the answer
                # and chunks from the text run.
                result["chunks"] = text_result.get("chunks")
                result["answer"] = text_result.get("answer", result.get("answer"))
                fallback_triggered = True

            payload = {
                "answer": result["answer"],
                "route": route,
                "route_reasoning": reasoning,
                "route_was_forced": was_forced,
                "fallback_triggered": fallback_triggered,
                "cypher": result.get("cypher"),
                "graph_row_count": result.get("graph_row_count"),
                "graph_results": result.get("graph_results"),
                "chunks": result.get("chunks"),
            }
            log.info(
                "rag_router_complete",
                route=route,
                was_forced=was_forced,
                fallback_triggered=fallback_triggered,
                graph_row_count=payload["graph_row_count"],
                n_chunks=len(payload["chunks"] or []),
                answer_chars=len(payload["answer"] or ""),
            )
            return payload

    # ---------- dispatch ----------

    def _dispatch(self, route: Route, question: str) -> dict[str, Any]:
        if route == "graph":
            return self._run_graph(question)
        if route == "text":
            return self._run_text(question)
        if route == "both":
            return self._run_both(question)
        # Defensive: should be unreachable given ROUTE_ENUM validation upstream.
        raise ValueError(f"unknown route: {route}")

    def _run_graph(self, question: str) -> dict[str, Any]:
        """Delegate to the existing text2cypher pipeline and normalize shape."""
        graph = self._text2cypher.query(question)
        return {
            "answer": graph.get("answer", ""),
            "cypher": graph.get("cypher"),
            "graph_row_count": graph.get("row_count", 0),
            "graph_results": graph.get("results") or [],
            "chunks": None,
        }

    def _run_text(self, question: str) -> dict[str, Any]:
        chunks = self._hybrid_search_safe(question)
        answer = self._generate_answer(question, chunks=chunks)
        return {
            "answer": answer,
            "cypher": None,
            "graph_row_count": None,
            "graph_results": None,
            "chunks": chunks,
        }

    def _run_both(self, question: str) -> dict[str, Any]:
        """Run graph + text branches in parallel; merge into a single answer LLM call."""
        with ThreadPoolExecutor(max_workers=2) as pool:
            graph_future = pool.submit(self._text2cypher.query, question)
            text_future = pool.submit(self._hybrid_search_safe, question)
            graph = graph_future.result()
            chunks = text_future.result()

        graph_results = graph.get("results") or []
        cypher = graph.get("cypher")
        answer = self._generate_answer(
            question,
            cypher=cypher,
            graph_results=graph_results,
            chunks=chunks,
        )
        return {
            "answer": answer,
            "cypher": cypher,
            "graph_row_count": graph.get("row_count", 0),
            "graph_results": graph_results,
            "chunks": chunks,
        }

    # ---------- helpers ----------

    def _hybrid_search_safe(self, question: str) -> list[dict[str, Any]]:
        try:
            return hybrid_search(query=question, top_k=TEXT_ROUTE_TOP_K)
        except Exception as e:
            log.warning("rag_router_hybrid_search_failed", error=str(e))
            return []

    def _generate_answer(
        self,
        question: str,
        cypher: str | None = None,
        graph_results: list[dict[str, Any]] | None = None,
        chunks: list[dict[str, Any]] | None = None,
    ) -> str:
        """Single prompt builder that adapts to whichever evidence slots are present."""
        sections: list[str] = [f"Question: {question}"]

        if cypher:
            sections.append(f"Cypher used:\n{cypher}")

        if graph_results is not None:
            sections.append(
                f"Knowledge-graph rows ({len(graph_results)}):\n"
                f"{json.dumps(graph_results[:50], indent=2, default=str)}"
            )

        if chunks:
            excerpts: list[str] = []
            for h in chunks:
                aid = h.get("advisory_id", "unknown")
                section = h.get("section_name") or ""
                sub = h.get("sub_section") or ""
                header_tail = (
                    f" §{section}" + (f" / {sub}" if sub else "") if section else ""
                )
                excerpts.append(f"[{aid}{header_tail}]\n{h.get('chunk_text', '')}")
            sections.append(
                "Relevant advisory passages (ranked by hybrid BM25+vector):\n"
                + "\n\n---\n".join(excerpts)
            )
        elif chunks is not None:
            sections.append("Relevant advisory passages: none found.")

        user_content = "\n\n".join(sections)

        record = self._llm.complete(
            task=LLMTask.ANSWER_GENERATION,
            messages=[
                {"role": "system", "content": ANSWER_SYSTEM},
                {"role": "user", "content": user_content},
            ],
            temperature=0,
            max_tokens=1200,
            extra_log={
                "stage": "answer_generation",
                "has_cypher": cypher is not None,
                "n_graph_rows": len(graph_results or []),
                "n_chunks": len(chunks or []),
            },
        )
        content = record.response.choices[0].message.content or ""
        return content.strip()


    def answer_stream(
        self,
        question: str,
        force_route: Route | None = None,
        disable_fallback: bool = False,
    ) -> Iterator[str]:
        """Like answer() but streams the final LLM response token-by-token.

        Routing + retrieval run synchronously first; only the answer-generation
        LLM call is streamed. Yields raw token strings.
        """
        route: Route
        if force_route is not None:
            route = force_route
        else:
            route, _ = choose_route(question)

        # --- retrieval (same logic as _dispatch but without answer generation) ---
        cypher: str | None = None
        graph_results: list[dict[str, Any]] = []
        chunks: list[dict[str, Any]] = []
        retrieval_error: str | None = None

        if route in ("graph", "both"):
            graph_data = self._text2cypher.retrieve(question)
            cypher = graph_data.get("cypher")
            graph_results = graph_data.get("results") or []
            retrieval_error = graph_data.get("error")

            if not disable_fallback and route == "graph" and graph_data.get("row_count", 0) == 0:
                # zero-row fallback: switch to text
                route = "text"
                chunks = self._hybrid_search_safe(question)
            elif route == "both":
                chunks = self._hybrid_search_safe(question)
        else:
            chunks = self._hybrid_search_safe(question)

        if retrieval_error and not graph_results and not chunks:
            yield retrieval_error
            return

        # --- build prompt (mirrors _generate_answer from both services) ---
        sections: list[str] = [f"Question: {question}"]
        if cypher:
            sections.append(f"Cypher used:\n{cypher}")
        if graph_results is not None:
            sections.append(
                f"Knowledge-graph rows ({len(graph_results)}):\n"
                f"{json.dumps(graph_results[:50], indent=2, default=str)}"
            )
        if chunks:
            excerpts: list[str] = []
            for h in chunks:
                aid = h.get("advisory_id", "unknown")
                section = h.get("section_name") or ""
                sub = h.get("sub_section") or ""
                header_tail = (f" §{section}" + (f" / {sub}" if sub else "")) if section else ""
                excerpts.append(f"[{aid}{header_tail}]\n{h.get('chunk_text', '')}")
            sections.append(
                "Relevant advisory passages (ranked by hybrid BM25+vector):\n"
                + "\n\n---\n".join(excerpts)
            )
        elif chunks is not None:
            sections.append("Relevant advisory passages: none found.")

        user_content = "\n\n".join(sections)

        yield from self._llm.stream_complete(
            task=LLMTask.ANSWER_GENERATION,
            messages=[
                {"role": "system", "content": ANSWER_SYSTEM},
                {"role": "user", "content": user_content},
            ],
            temperature=0,
            max_tokens=1200,
            extra_log={"stage": "answer_generation_stream"},
        )


_service: RAGRouterService | None = None


def get_rag_router_service() -> RAGRouterService:
    global _service
    if _service is None:
        _service = RAGRouterService()
    return _service
