"""Text2Cypher RAG service: natural language -> Cypher -> Neo4j -> answer.

Structured logging: events are emitted via structlog with a stable `event`
name + key/value fields. A per-query `request_id` + `question_preview` is
bound via contextvars at the top of `query()`, so every nested log line
(including those inside `_generate_cypher` / `_generate_answer`) inherits
that context without the helpers having to thread it through by hand.
"""
import json
import uuid
from typing import Any

import structlog
from pydantic import BaseModel, Field, ValidationError
from structlog.contextvars import bound_contextvars

from app.services.hybrid_search import hybrid_search
from app.services.llm_router import LLMTask, get_llm_router
from app.services.neo4j_service import get_neo4j_service

log = structlog.get_logger(__name__)

MAX_CYPHER_ATTEMPTS = 3


class CypherResponse(BaseModel):
    """Structured output for NL->Cypher generation.

    Using OpenAI structured output eliminates the markdown fence parsing that
    the old string-based path had to do, and forces an explicit can_answer
    signal instead of a fragile "null" string sentinel.
    """
    can_answer: bool = Field(
        description="True if the question can be answered with the graph schema."
    )
    cypher: str | None = Field(
        description="Valid read-only Cypher query, or null when can_answer is false."
    )
    reasoning: str = Field(
        description="One short sentence explaining the chosen pattern or why unanswerable."
    )

GRAPH_SCHEMA = """
Node labels and key properties:
  Actor     {name: string}              -- threat actor / nation-state group
  Malware   {name: string}              -- malware, ransomware, tool, backdoor
  Technique {name: string}              -- attack technique (may reference MITRE ATT&CK)
  Tactic    {name: string}              -- MITRE ATT&CK tactic
  Campaign  {name: string}              -- named attack campaign
  Other     {name: string}              -- generic entity (IP, domain, file, product, org)
  CVE       {id: string, description_en: string, is_kev: boolean}  -- vulnerability (e.g. CVE-2023-1234)
  CWE       {id: string, name: string}                             -- weakness (e.g. CWE-79)

Relationship types:
  (Actor|Malware)-[:USES]->(Malware|Technique|Other)
  (Actor|Malware)-[:TARGETS]->(Other)
  (Actor|Malware)-[:EXPLOITS]->(CVE)
  (Malware|Campaign)-[:ATTRIBUTED_TO]->(Actor)
  (CVE|Malware)-[:AFFECTS]->(Other)
  (CVE)-[:HAS_WEAKNESS]->(CWE)
  (Other|Technique)-[:MITIGATES]->(Actor|Malware|CVE)

All relationships have:
  advisory_id : string   -- CISA advisory that sourced this edge
  is_inferred : boolean  -- false = directly extracted, true = LLM-inferred
"""

FEW_SHOT_EXAMPLES = """
Example 1 — simple actor → malware:
Q: What malware does APT41 use?
Cypher:
  MATCH (a:Actor)-[r:USES]->(m:Malware)
  WHERE toLower(a.name) CONTAINS toLower('APT41')
  RETURN a.name, m.name, r.advisory_id
  LIMIT 50

Example 2 — USES polymorphism (Malware/Technique/Other):
Q: What tools and techniques does Volt Typhoon use?
Cypher:
  MATCH (a:Actor)-[r:USES]->(n)
  WHERE toLower(a.name) CONTAINS toLower('Volt Typhoon')
    AND (n:Malware OR n:Technique OR n:Other)
  RETURN a.name, labels(n)[0] AS target_type, n.name, r.advisory_id
  LIMIT 50

Example 3 — CVE with description and KEV flag:
Q: Which CVEs does the LockBit ransomware exploit?
Cypher:
  MATCH (m:Malware)-[r:EXPLOITS]->(c:CVE)
  WHERE toLower(m.name) CONTAINS toLower('LockBit')
  RETURN m.name, c.id, c.description_en, c.is_kev, r.advisory_id
  LIMIT 50

Example 4 — aggregation (no LIMIT for counts):
Q: How many threat actors are tracked in the graph?
Cypher:
  MATCH (a:Actor) RETURN count(a) AS actor_count

Example 5 — KEV filter + actor attribution:
Q: Which known-exploited CVEs are linked to any threat actor?
Cypher:
  MATCH (a:Actor)-[r:EXPLOITS]->(c:CVE)
  WHERE c.is_kev = true
  RETURN a.name, c.id, c.description_en, r.advisory_id
  LIMIT 50

Example 6 — tool name that may be stored as Technique OR Other:
Q: Which actors use brute force attacks?
Cypher:
  MATCH (a:Actor)-[r:USES]->(n)
  WHERE (n:Technique OR n:Other)
    AND toLower(n.name) CONTAINS toLower('brute force')
  RETURN a.name, labels(n)[0] AS target_type, n.name, r.advisory_id
  LIMIT 50

Example 7 — unanswerable (out of schema):
Q: What's the latest cybersecurity news today?
→ can_answer=false, cypher=null
"""

CYPHER_SYSTEM = f"""You are a Neo4j Cypher expert for a Cyber Threat Intelligence knowledge graph.

Graph schema:
{GRAPH_SCHEMA}

Rules:
- Use only MATCH, WHERE, RETURN (no write clauses — no CREATE/MERGE/DELETE/SET)
- For name matching use: toLower(n.name) CONTAINS toLower('term')
- For CVE/CWE use the id property, not name; when returning CVEs also include description_en
- Always LIMIT results to 50 unless the question asks for counts/aggregations
- When querying what an actor/malware USES, the target can be Malware, Technique, OR Other —
  use: MATCH (a)-[r:USES]->(n) WHERE (n:Malware OR n:Technique OR n:Other)
- When searching by tool/technique name (e.g. brute force, spearphishing), search both
  Technique and Other labels since tools may be stored under either
- ALWAYS name the relationship variable so r.advisory_id can be returned.
  CORRECT:   MATCH (a:Actor)-[r:USES]->(m:Malware) RETURN m.name, r.advisory_id
  INCORRECT: MATCH (a:Actor)-[:USES]->(m:Malware)  RETURN m.name, r.advisory_id
- If the question cannot be answered from the schema, set can_answer=false and cypher=null.

Examples:
{FEW_SHOT_EXAMPLES}

Respond using the structured output schema: {{can_answer, cypher, reasoning}}.
The cypher field must contain ONLY a raw Cypher query — no markdown, no code fences, no prose."""

ANSWER_SYSTEM = """You are a cybersecurity analyst writing a detailed threat intelligence report based on knowledge graph query results and CISA advisory excerpts.
Given the user's question, raw Neo4j results, and relevant CISA advisory excerpts, write a thorough answer.
- Use bullet points to organize the answer, do not use markdown headers
- For each finding, explain what it means in a threat intelligence context
- Cite advisory IDs (e.g. aa22-011a) when referencing specific facts
- Include context about why each finding matters (impact, severity, common usage)
- If results are empty, say no matching data was found
- Aim for 400-600 words"""


class Text2CypherService:
    def __init__(self):
        self._router = get_llm_router()
        self._neo4j = get_neo4j_service()

    def _fetch_relevant_chunks(
        self, question: str, advisory_ids: list[str], top_k: int = 10
    ) -> list[dict[str, Any]]:
        """Rank chunks within the graph-selected advisories using hybrid BM25+vector.

        This is the Hybrid Graph RAG bridge: the graph picks which advisories are
        relevant (via advisory_id on edges), and hybrid_search picks which
        passages within those advisories are most relevant to the question.
        """
        if not advisory_ids:
            return []
        return hybrid_search(
            query=question,
            top_k=top_k,
            advisory_ids=advisory_ids,
        )

    def _generate_cypher(
        self,
        question: str,
        prior_attempt: dict[str, str] | None = None,
    ) -> tuple[str | None, str]:
        """Generate Cypher via OpenAI structured output.

        Returns (cypher, reasoning). cypher=None when the LLM declines
        (can_answer=false). When `prior_attempt` is provided, its failing
        cypher + Neo4j error message are fed back so the LLM can self-correct.
        """
        if prior_attempt:
            user_msg = (
                f"Question: {question}\n\n"
                f"Your previous Cypher attempt failed:\n{prior_attempt['cypher']}\n\n"
                f"Error from Neo4j:\n{prior_attempt['error']}\n\n"
                "Fix the query and try again. If the question cannot be answered "
                "from the schema, set can_answer=false."
            )
        else:
            user_msg = question

        try:
            record = self._router.complete(
                task=LLMTask.CYPHER_GENERATION,
                messages=[
                    {"role": "system", "content": CYPHER_SYSTEM},
                    {"role": "user", "content": user_msg},
                ],
                response_format=CypherResponse,
                temperature=0,
                max_tokens=500,
                extra_log={"stage": "cypher_generation", "has_prior_attempt": prior_attempt is not None},
            )
        except Exception as e:
            log.exception("cypher_llm_call_failed", has_prior_attempt=prior_attempt is not None)
            return None, f"LLM call failed: {e}"

        # LiteLLM returns structured output as a JSON string in message.content
        # rather than a hydrated Pydantic object, so we parse it ourselves.
        content = record.response.choices[0].message.content
        if not content:
            log.warning("cypher_llm_empty_content", request_id=record.request_id)
            return None, "LLM returned empty content"
        try:
            parsed = CypherResponse.model_validate_json(content)
        except ValidationError as e:
            log.warning(
                "cypher_schema_validation_failed",
                request_id=record.request_id,
                error=str(e),
                content_preview=content[:200],
            )
            return None, f"Invalid structured output: {e}"

        if not parsed.can_answer or not parsed.cypher:
            log.info(
                "cypher_declined",
                request_id=record.request_id,
                reasoning=parsed.reasoning,
            )
            return None, parsed.reasoning
        return parsed.cypher.strip(), parsed.reasoning

    def _generate_answer(self, question: str, cypher: str, results: list[dict],
                         advisory_chunks: list[dict[str, Any]]) -> str:
        advisories_section = ""
        if advisory_chunks:
            excerpts = []
            for h in advisory_chunks:
                aid = h.get("advisory_id", "unknown")
                section = h.get("section_name") or ""
                sub = h.get("sub_section") or ""
                header_tail = f" §{section}" + (f" / {sub}" if sub else "") if section else ""
                excerpts.append(f"[{aid}{header_tail}]\n{h.get('chunk_text', '')}")
            advisories_section = (
                "\n\nRelevant advisory passages (ranked by hybrid BM25+vector):\n"
                + "\n\n---\n".join(excerpts)
            )

        user_content = f"""Question: {question}

Cypher used:
{cypher}

Raw results ({len(results)} rows):
{json.dumps(results[:50], indent=2, default=str)}{advisories_section}"""

        record = self._router.complete(
            task=LLMTask.ANSWER_GENERATION,
            messages=[
                {"role": "system", "content": ANSWER_SYSTEM},
                {"role": "user", "content": user_content},
            ],
            temperature=0,
            max_tokens=1200,
            extra_log={
                "stage": "answer_generation",
                "n_results": len(results),
                "n_chunks": len(advisory_chunks),
            },
        )
        return record.response.choices[0].message.content.strip()

    def query(self, question: str) -> dict[str, Any]:
        request_id = uuid.uuid4().hex[:12]
        # Bind contextvars so every nested log line (including from
        # _generate_cypher / _generate_answer) carries request_id + question
        # without us having to pass a bound logger through each helper.
        with bound_contextvars(
            request_id=request_id,
            question_preview=question[:160],
        ):
            log.info("text2cypher_query_start")

            cypher: str | None = None
            reasoning = ""
            last_error: str | None = None
            results: list[dict] | None = None

            # Retry loop: if Neo4j rejects the Cypher, feed the error back to the
            # LLM so it can self-correct. We stop on success, on LLM giving up
            # (can_answer=false), or after MAX_CYPHER_ATTEMPTS.
            for attempt in range(MAX_CYPHER_ATTEMPTS):
                prior = (
                    {"cypher": cypher, "error": last_error}
                    if last_error and cypher is not None
                    else None
                )
                cypher, reasoning = self._generate_cypher(question, prior)

                if cypher is None:
                    if attempt == 0:
                        log.info("text2cypher_unanswerable", reasoning=reasoning)
                        msg = (
                            f"This question cannot be answered from the "
                            f"knowledge graph schema. ({reasoning})"
                        )
                    else:
                        log.warning(
                            "text2cypher_gave_up",
                            attempts=attempt,
                            last_error=last_error,
                            reasoning=reasoning,
                        )
                        msg = (
                            f"Could not produce a valid Cypher after {attempt} "
                            f"retry(ies). Last Neo4j error: {last_error}. "
                            f"LLM note: {reasoning}"
                        )
                    return {
                        "answer": msg,
                        "cypher": None,
                        "results": [],
                        "row_count": 0,
                    }

                log.info(
                    "cypher_generated",
                    attempt=attempt + 1,
                    cypher=cypher,
                    reasoning=reasoning,
                )

                try:
                    results = self._neo4j.execute_query(cypher)
                    log.info(
                        "cypher_executed",
                        attempt=attempt + 1,
                        row_count=len(results),
                    )
                    break
                except Exception as e:
                    last_error = str(e)
                    log.warning(
                        "cypher_execution_failed",
                        attempt=attempt + 1,
                        error=last_error,
                        cypher=cypher,
                    )

            if results is None:
                log.error(
                    "text2cypher_retries_exhausted",
                    max_attempts=MAX_CYPHER_ATTEMPTS,
                    last_error=last_error,
                )
                return {
                    "answer": (
                        f"Cypher execution failed after {MAX_CYPHER_ATTEMPTS} attempts. "
                        f"Last error: {last_error}"
                    ),
                    "cypher": cypher,
                    "results": [],
                    "row_count": 0,
                }

            # Extract advisory_ids from results (any key containing advisory_id).
            # Wider cap than before: we no longer dump each advisory's full text,
            # we just use these as a metadata filter for chunk-level hybrid search.
            advisory_ids = list({
                v for row in results
                for k, v in row.items()
                if "advisory_id" in k and isinstance(v, str)
            })[:20]

            advisory_chunks: list[dict[str, Any]] = []
            if advisory_ids:
                try:
                    advisory_chunks = self._fetch_relevant_chunks(question, advisory_ids)
                except Exception as e:
                    log.warning(
                        "advisory_chunks_fetch_failed",
                        error=str(e),
                        n_advisory_ids=len(advisory_ids),
                    )

            answer = self._generate_answer(question, cypher, results, advisory_chunks)

            log.info(
                "text2cypher_query_complete",
                row_count=len(results),
                n_advisory_ids=len(advisory_ids),
                n_chunks=len(advisory_chunks),
                answer_chars=len(answer),
            )

            return {
                "answer": answer,
                "cypher": cypher,
                "results": results[:50],
                "row_count": len(results),
            }


    def retrieve(self, question: str) -> dict[str, Any]:
        """Run Cypher generation + execution + chunk fetching without generating an answer.

        Returns: {cypher, results, advisory_chunks, row_count, error}
        Used by the streaming endpoint so answer generation can be streamed separately.
        """
        request_id = uuid.uuid4().hex[:12]
        with bound_contextvars(request_id=request_id, question_preview=question[:160]):
            cypher: str | None = None
            last_error: str | None = None
            results: list[dict] | None = None

            for attempt in range(MAX_CYPHER_ATTEMPTS):
                prior = (
                    {"cypher": cypher, "error": last_error}
                    if last_error and cypher is not None
                    else None
                )
                cypher, reasoning = self._generate_cypher(question, prior)

                if cypher is None:
                    msg = (
                        f"This question cannot be answered from the knowledge graph schema. ({reasoning})"
                        if attempt == 0
                        else f"Could not produce valid Cypher after {attempt} retry(ies). Last error: {last_error}"
                    )
                    return {"cypher": None, "results": [], "advisory_chunks": [], "row_count": 0, "error": msg}

                try:
                    results = self._neo4j.execute_query(cypher)
                    break
                except Exception as e:
                    last_error = str(e)

            if results is None:
                return {
                    "cypher": cypher,
                    "results": [],
                    "advisory_chunks": [],
                    "row_count": 0,
                    "error": f"Cypher execution failed after {MAX_CYPHER_ATTEMPTS} attempts. Last error: {last_error}",
                }

            advisory_ids = list({
                v for row in results
                for k, v in row.items()
                if "advisory_id" in k and isinstance(v, str)
            })[:20]

            advisory_chunks: list[dict[str, Any]] = []
            if advisory_ids:
                try:
                    advisory_chunks = self._fetch_relevant_chunks(question, advisory_ids)
                except Exception as e:
                    log.warning("advisory_chunks_fetch_failed", error=str(e))

            return {
                "cypher": cypher,
                "results": results[:50],
                "advisory_chunks": advisory_chunks,
                "row_count": len(results),
                "error": None,
            }


_service: Text2CypherService | None = None


def get_text2cypher_service() -> Text2CypherService:
    global _service
    if _service is None:
        _service = Text2CypherService()
    return _service
