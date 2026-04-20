"""Single source of truth for the search-tool schema.

Shared between:
  - app/routers/hybrid_search.py       — FastAPI request model
  - app/services/doctype_classifier.py — OpenAI tool-calling simulation
  - (future) MCP server tool registration

Keeping the doc_type description in one place means the accuracy we measure
in the eval notebook is the same accuracy a real MCP agent will see — the
LLM reads the same text either way.
"""

DOC_TYPE_ENUM: list[str] = [
    "MAR",
    "ANALYSIS_REPORT",
    "JOINT_CSA",
    "STOPRANSOMWARE",
    "IR_LESSONS",
    "CSA",
]

DOC_TYPE_DESCRIPTION: str = (
    "Filter narrowing the search to specific CISA document types. "
    "Almost always pass 1 or 2 types — filtering helps retrieval even when "
    "you're not certain. Pass 1 when the query clearly targets a single "
    "category; pass 2 when it's genuinely ambiguous between two. Only omit "
    "entirely if the query could plausibly match 3+ types (e.g., broad "
    "security advice with no topical signal at all).\n"
    "- MAR: malware analysis reports, per-sample reverse engineering. "
    "Pick this for questions about specific malware samples, hashes, YARA "
    "rules, PE32/ELF binary analysis, MAR-XXXXXXXX IDs, or named malware "
    "families (HOPLIGHT, TAIDOOR, BLINDINGCAN, GRAT2, etc.).\n"
    "- ANALYSIS_REPORT: non-MAR technical analyses. Pick this for attack "
    "chain walkthroughs, tool forensics not tied to one malware sample, "
    "or advisories with ar20-XXX / AR-XXXX IDs.\n"
    "- JOINT_CSA: multi-agency cybersecurity advisories. Pick this for "
    "questions about nation-state APT campaigns (Russian, Iranian, PRC, "
    "DPRK actors), advisories co-sealed by FBI/CISA/NSA or foreign "
    "agencies, which countries collaborated, or aa23-XXX IDs.\n"
    "- STOPRANSOMWARE: #StopRansomware joint advisories. Pick this for "
    "questions about named ransomware families (BlackCat/ALPHV, LockBit, "
    "Conti, Royal, Play, Akira, etc.), ransomware TTPs, or affiliate "
    "behavior.\n"
    "- IR_LESSONS: incident response retrospectives and red team "
    "assessments. Pick this for 'lessons learned', post-incident "
    "analysis, red team engagement findings, or retrospective framing.\n"
    "- CSA: single-agency CISA advisories. Pick this for product-specific "
    "alerts (Pulse Connect Secure, Kubernetes, Log4j, etc.), patch "
    "management guidance, or single-agency CISA guidance without "
    "multi-agency co-sealing.\n"
    "Tips: Questions about 'which countries' or 'collaborated' almost "
    "always mean JOINT_CSA. Questions naming a ransomware family mean "
    "STOPRANSOMWARE. Questions about hashes or specific samples mean MAR. "
    "When CSA vs JOINT_CSA is unclear, pass both."
)

SEARCH_TOOL_NAME: str = "search_advisories"

SEARCH_TOOL_DESCRIPTION: str = (
    "Hybrid BM25 + vector search over CISA cybersecurity advisory chunks. "
    "Use for questions about vulnerabilities, malware, threat actors, "
    "incident response, or security recommendations."
)

SEARCH_TOOL: dict = {
    "type": "function",
    "function": {
        "name": SEARCH_TOOL_NAME,
        "description": SEARCH_TOOL_DESCRIPTION,
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The user's question, passed verbatim.",
                },
                "document_types": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": DOC_TYPE_ENUM,
                    },
                    "description": DOC_TYPE_DESCRIPTION,
                },
            },
            "required": ["query"],
        },
    },
}

CLASSIFIER_SYSTEM_PROMPT: str = (
    "You are a cybersecurity research assistant. Use the "
    f"{SEARCH_TOOL_NAME} tool to answer the user's question. "
    "Filtering by document_types substantially improves retrieval, so "
    "almost always pass 1 or 2 types — read the tool's document_types "
    "description carefully and commit to a best guess. Pass 2 only when "
    "genuinely ambiguous between two categories; omit entirely only for "
    "queries so generic that 3+ types are equally likely."
)
