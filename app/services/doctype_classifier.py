"""MCP-style doc_type classifier via OpenAI tool calling.

Simulates what a real MCP agent does: given the `search_advisories` tool
schema, the LLM decides whether to pass `document_types` and which values.
An empty list means the LLM chose not to filter — treat it as `None` at
the retrieval layer.

Used by:
  - scripts/build_eval_notebook.py (measure tool-call agreement + run
    retrieval eval with LLM-predicted filters)
  - (future) production path, if the eval shows the gap to oracle is small
    enough to justify the OpenAI round-trip.
"""

import json
import logging
from typing import Optional

from app.services.llm_router import LLMRouter, LLMTask, get_llm_router
from app.services.search_tool_schema import (
    CLASSIFIER_SYSTEM_PROMPT,
    DOC_TYPE_ENUM,
    SEARCH_TOOL,
    SEARCH_TOOL_NAME,
)

logger = logging.getLogger(__name__)

_DOC_TYPE_SET = set(DOC_TYPE_ENUM)


def classify_doctype(
    query: str,
    router: Optional[LLMRouter] = None,
    model_override: Optional[str] = None,
) -> list[str]:
    """Ask an LLM how it would call `search_advisories` for this query.

    Returns the `document_types` the LLM chose, which may be:
      - `[]` — LLM chose not to filter (ambiguous / multi-type query)
      - `["MAR"]` — single confident type
      - `["MAR", "CSA"]` — LLM hedged between two types

    Caller treats `[]` as "no filter" (equivalent to passing None to
    hybrid_search). Unknown / invalid types are silently dropped so one
    hallucinated value doesn't collapse retrieval to zero hits.
    """
    if router is None:
        router = get_llm_router()

    record = router.complete(
        task=LLMTask.DOCTYPE_CLASSIFICATION,
        messages=[
            {"role": "system", "content": CLASSIFIER_SYSTEM_PROMPT},
            {"role": "user", "content": query},
        ],
        tools=[SEARCH_TOOL],
        tool_choice={
            "type": "function",
            "function": {"name": SEARCH_TOOL_NAME},
        },
        temperature=0,
        model_override=model_override,
        extra_log={"stage": "doctype_classification"},
    )

    msg = record.response.choices[0].message
    tool_calls = msg.tool_calls or []
    if not tool_calls:
        logger.warning("[doctype_clf] no tool_call returned for query=%r", query)
        return []

    try:
        args = json.loads(tool_calls[0].function.arguments)
    except (json.JSONDecodeError, AttributeError) as e:
        logger.warning("[doctype_clf] bad tool args (%s) for query=%r", e, query)
        return []

    raw = args.get("document_types") or []
    if not isinstance(raw, list):
        return []
    # Drop anything that's not in the enum — a real MCP server would reject
    # these at schema validation; we just filter silently here.
    return [t for t in raw if isinstance(t, str) and t in _DOC_TYPE_SET]
