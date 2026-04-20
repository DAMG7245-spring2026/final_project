"""Text2Cypher RAG service: natural language -> Cypher -> Neo4j -> answer."""
import json
import logging
from typing import Any

from openai import OpenAI

from app.config import get_settings
from app.services.neo4j_service import get_neo4j_service
from app.services.snowflake import get_snowflake_service

logger = logging.getLogger(__name__)

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

CYPHER_SYSTEM = f"""You are a Neo4j Cypher expert for a Cyber Threat Intelligence knowledge graph.

Graph schema:
{GRAPH_SCHEMA}

Rules:
- Use only MATCH, WHERE, RETURN (no write clauses)
- For name matching use: toLower(n.name) CONTAINS toLower('term')
- For CVE/CWE use the id property, not name; when returning CVEs also include description_en
- Always LIMIT results to 50 unless the question asks for counts
- When querying what an actor/malware uses, the target can be Malware, Technique, OR Other — always use: MATCH (a)-[r:USES]->(n) WHERE (n:Malware OR n:Technique OR n:Other)
- When searching for a specific tool or technique by name (e.g. brute force, spearphishing), search both Technique and Other labels since tools may be stored under either
- ALWAYS name the relationship variable so r.advisory_id can be returned.
  CORRECT:   MATCH (a:Actor)-[r:USES]->(m:Malware) RETURN m.name, r.advisory_id
  INCORRECT: MATCH (a:Actor)-[:USES]->(m:Malware)  RETURN m.name, r.advisory_id
- If the question cannot be answered from the schema, return exactly: null

Respond with ONLY a valid Cypher query string, or null. No explanation, no markdown."""

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
        s = get_settings()
        self._client = OpenAI(api_key=s.openai_api_key)
        self._neo4j = get_neo4j_service()
        self._snowflake = get_snowflake_service()

    def _fetch_advisory_texts(self, advisory_ids: list[str]) -> dict[str, str]:
        if not advisory_ids:
            return {}
        placeholders = ", ".join(["%s"] * len(advisory_ids))
        rows = self._snowflake.execute_query(
            f"""
            SELECT advisory_id, LISTAGG(chunk_text, '\n\n') WITHIN GROUP (ORDER BY chunk_index) AS body
            FROM advisory_chunks
            WHERE advisory_id IN ({placeholders})
            GROUP BY advisory_id
            """,
            tuple(advisory_ids),
        )
        return {r["advisory_id"]: r["body"] for r in rows}

    def _generate_cypher(self, question: str) -> str | None:
        response = self._client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": CYPHER_SYSTEM},
                {"role": "user", "content": question},
            ],
            temperature=0,
            max_tokens=300,
        )
        raw = response.choices[0].message.content.strip()
        if raw.lower() == "null" or not raw:
            return None
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1]
            if raw.startswith("cypher"):
                raw = raw[6:]
        return raw.strip()

    def _generate_answer(self, question: str, cypher: str, results: list[dict],
                         advisory_texts: dict[str, str]) -> str:
        advisories_section = ""
        if advisory_texts:
            excerpts = []
            for aid, text in advisory_texts.items():
                excerpts.append(f"[{aid}]\n{text[:3000]}")
            advisories_section = "\n\nSource advisory excerpts:\n" + "\n\n---\n".join(excerpts)

        user_content = f"""Question: {question}

Cypher used:
{cypher}

Raw results ({len(results)} rows):
{json.dumps(results[:50], indent=2, default=str)}{advisories_section}"""

        response = self._client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": ANSWER_SYSTEM},
                {"role": "user", "content": user_content},
            ],
            temperature=0,
            max_tokens=1200,
        )
        return response.choices[0].message.content.strip()

    def query(self, question: str) -> dict[str, Any]:
        cypher = self._generate_cypher(question)
        if cypher is None:
            return {
                "answer": "This question cannot be answered from the knowledge graph schema.",
                "cypher": None,
                "results": [],
                "row_count": 0,
            }

        logger.info(f"Generated Cypher: {cypher}")

        try:
            results = self._neo4j.execute_query(cypher)
        except Exception as e:
            logger.error(f"Cypher execution failed: {e}")
            return {
                "answer": f"Query execution failed: {e}",
                "cypher": cypher,
                "results": [],
                "row_count": 0,
            }

        # Extract advisory_ids from results (any key containing advisory_id)
        advisory_ids = list({
            v for row in results
            for k, v in row.items()
            if "advisory_id" in k and isinstance(v, str)
        })[:5]  # cap at 5 advisories to keep prompt size manageable

        advisory_texts = {}
        if advisory_ids:
            try:
                advisory_texts = self._fetch_advisory_texts(advisory_ids)
            except Exception as e:
                logger.warning(f"Failed to fetch advisory texts: {e}")

        answer = self._generate_answer(question, cypher, results, advisory_texts)

        return {
            "answer": answer,
            "cypher": cypher,
            "results": results[:50],
            "row_count": len(results),
        }


_service: Text2CypherService | None = None


def get_text2cypher_service() -> Text2CypherService:
    global _service
    if _service is None:
        _service = Text2CypherService()
    return _service
