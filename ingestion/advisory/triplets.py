"""
Advisory triplet pipeline (Phase 1–4) refactored for DAG use.

  Phase 1 — run_extract_triplets : kNN ICL + GPT-4o  → ``extracted_triplets``
  Phase 2 — run_align_entities   : entity dedup       → ``entity_aliases`` + triplets rewrite
  Phase 4 — run_load_neo4j       : Snowflake → Neo4j  (MERGE nodes + edges)
  Phase 3 — run_infer_relations  : close disconnected subgraphs → inferred edges in Neo4j

Convention for ``advisory_ids`` mirrors ``ingestion.advisory.chunk_loader``:
  * ``None``      → full scope (Phase 1/4/3 run over every eligible advisory;
                    Phase 2 always sweeps the whole triplets table).
  * ``[]``        → no-op (fast path when the scraper found nothing new).
  * ``[a, b, …]`` → limit to those advisory_ids (Phase 2 still runs globally).
"""

from __future__ import annotations

import json
import logging
import re
from time import perf_counter
from typing import Any, Iterable
from uuid import uuid4

logger = logging.getLogger(__name__)


# ── Shared constants ──────────────────────────────────────────────────────────

RELATION_WHITELIST = {
    "uses", "targets", "exploits", "attributed_to",
    "affects", "has_weakness", "mitigates",
}

RELATION_MAP = {
    "uses": "USES",
    "targets": "TARGETS",
    "exploits": "EXPLOITS",
    "attributed_to": "ATTRIBUTED_TO",
    "affects": "AFFECTS",
    "has_weakness": "HAS_WEAKNESS",
    "mitigates": "MITIGATES",
}

LABEL_MAP = {
    "actor": "Actor",
    "software": "Malware",
    "technique": "Technique",
    "tactic": "Tactic",
    "campaign": "Campaign",
    "other": "Other",
}

ENTITY_TYPES = {
    "cve", "cwe", "technique", "tactic",
    "actor", "software", "campaign", "other",
}

VAGUE_TERMS = {
    "the attacker", "the attackers", "attacker", "attackers",
    "malicious actors", "malicious cyber actors", "threat actors",
    "the threat actor", "threat actor", "the malware", "malware",
    "cyber actors", "the group", "the adversary", "adversary",
    "apt actors", "apt actor", "the actor", "actor",
}

TOP_K_DEMOS = 4
ENTITY_EMBED_MODEL = "snowflake-arctic-embed-l-v2.0"
DEFAULT_SIM_THRESHOLD = 0.85

CVE_RE    = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
CWE_RE    = re.compile(r"^CWE-\d+$", re.IGNORECASE)
TECH_RE   = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
TACTIC_RE = re.compile(r"^TA\d{4}$", re.IGNORECASE)
IP_RE     = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HASH_RE   = re.compile(r"^[0-9a-fA-F]{16,}$")


# ── Prompts ───────────────────────────────────────────────────────────────────

EXTRACT_SYSTEM_PROMPT = """You are a cybersecurity analyst. Extract (subject, relation, object) triplets from the threat intelligence report provided.

Rules:
- ONLY use these relations: {relations}
- Subject and object MUST be specific named entities: threat actor names (e.g. APT29, Lazarus Group), malware families (e.g. DarkSide, Cobalt Strike), CVE IDs (e.g. CVE-2021-44228), CWE IDs, MITRE technique IDs (e.g. T1059), product names (e.g. Microsoft Exchange), organization names, industry sectors, etc.
- Do NOT use vague subjects/objects like "the attacker", "malicious actors", "threat actors", "the malware"
- Do NOT extract defensive recommendations as triplets
- Each triplet must represent a factual claim directly stated in the report
- Return a JSON array of objects with keys: "subject", "relation", "object"
- If no valid triplets can be extracted, return []"""

CLASSIFY_ENTITY_PROMPT = """You are a cybersecurity knowledge graph expert.
Classify the given entity name into exactly one of these types:
  cve       — CVE identifier (e.g. CVE-2021-44228)
  cwe       — CWE identifier (e.g. CWE-79)
  technique — MITRE ATT&CK technique or sub-technique (e.g. T1059, T1059.001)
  tactic    — MITRE ATT&CK tactic (e.g. TA0001, Initial Access)
  actor     — threat actor, APT group, nation-state group, hacker group
  software  — malware, ransomware, tool, exploit kit, backdoor
  campaign  — named cyber campaign or operation
  other     — anything else (product, organization, sector, country, IP, etc.)

Respond with a single JSON object: {"entity_type": "<type>"}
No explanation."""

ALIGN_PAIR_PROMPT = """You are a cybersecurity knowledge graph expert.
Given two entity names from threat intelligence reports, determine:
1. Are they the same real-world entity? (yes/no)
2. If yes, which name is the canonical (most widely used) name?

Respond with a single JSON object:
{"same_entity": true/false, "canonical_name": "<name or null>"}
No explanation."""

INFER_RELATION_PROMPT = """You are a cybersecurity analyst. Two entities appear in the same threat intelligence report.
Based on the report content, determine the relationship between them.

Choose exactly one relation from:
  uses         — actor/malware uses a tool, technique, or infrastructure
  targets      — actor/malware targets an organization, sector, or country
  exploits     — actor/malware exploits a specific vulnerability (CVE)
  attributed_to — activity/malware attributed to a threat actor
  affects      — vulnerability or malware affects a product/system
  has_weakness — CVE has a specific weakness (CWE)
  mitigates    — action or control mitigates a threat

If there is NO clear relationship between the two entities in this report, return null.

Respond with a single JSON object:
  {"subject": "<entity>", "relation": "<relation>", "object": "<entity>"}
or:
  null

No explanation."""

VALIDATE_INFERENCE_PROMPT = """You are a cybersecurity knowledge graph validator.
Given a proposed triplet (subject → relation → object), decide if it is semantically valid for a CTI knowledge graph.

Rules:
- "uses": subject must be a threat actor, malware, or tool — NOT a vulnerability or file artifact
- "targets": subject must be a threat actor or malware
- "exploits": subject must be a threat actor or malware; object must be a CVE
- "attributed_to": object must be a threat actor or nation-state
- "affects": subject must be a CVE or malware; object must be a product/system
- "has_weakness": subject must be a CVE; object must be a CWE
- "mitigates": object must be a threat, malware, or vulnerability

Also check: is the direction logically correct? (e.g., a DLL file cannot "use" a threat actor)

Respond with a single JSON object: {"valid": true} or {"valid": false}
No explanation."""


# ── Service helpers ───────────────────────────────────────────────────────────

def _get_snowflake_service():
    from app.services.snowflake import get_snowflake_service
    return get_snowflake_service()


def _get_neo4j_driver():
    from app.services.neo4j_service import get_neo4j_service
    return get_neo4j_service().connect()


def _get_openai_client():
    from app.config import get_settings
    from openai import OpenAI
    return OpenAI(api_key=get_settings().openai_api_key)


def _log_llm(cur, *, pipeline_stage: str, model: str, usage, advisory_id: str | None = None) -> None:
    if usage is None:
        return
    try:
        from app.token_logger import log_llm_call
        log_llm_call(
            pipeline_stage=pipeline_stage,
            model=model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            advisory_id=advisory_id,
            cur=cur,
        )
    except Exception as e:
        logger.warning("token_log_failed stage=%s error=%s", pipeline_stage, e)


def _skip_result(run_id: str, reason: str, started: float, commit: bool) -> dict[str, Any]:
    elapsed = perf_counter() - started
    logger.info("triplets_skip run_id=%s reason=%s elapsed_sec=%.3f", run_id, reason, elapsed)
    return {
        "run_id": run_id,
        "skipped": True,
        "reason": reason,
        "dry_run": not commit,
        "elapsed_sec": elapsed,
    }


# ── Entity classification helpers (shared by Phase 2 & 4) ─────────────────────

def _pattern_classify_entity(name: str) -> str | None:
    if CVE_RE.match(name):
        return "cve"
    if CWE_RE.match(name):
        return "cwe"
    if TACTIC_RE.match(name):
        return "tactic"
    if TECH_RE.match(name):
        return "technique"
    return None


def _llm_classify_entity(name: str, client, model: str, cur=None) -> str:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": CLASSIFY_ENTITY_PROMPT},
                {"role": "user", "content": f'Entity name: "{name}"'},
            ],
            temperature=0,
            max_tokens=30,
        )
        _log_llm(cur, pipeline_stage="entity_classify", model=model, usage=response.usage)
        raw = response.choices[0].message.content.strip()
        parsed = json.loads(raw)
        etype = parsed.get("entity_type", "other")
        return etype if etype in ENTITY_TYPES else "other"
    except Exception as e:
        logger.warning("entity_classify_failed name=%s error=%s", name, e)
        return "other"


def _is_named_entity(name: str) -> bool:
    if IP_RE.match(name):
        return False
    if HASH_RE.match(name):
        return False
    if len(name) < 3:
        return False
    return True


# ────────────────────────────────────────────────────────────────────────────
# Phase 1 — run_extract_triplets
# ────────────────────────────────────────────────────────────────────────────

def _parse_llm_json_array(raw: str) -> list[dict]:
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    return json.loads(text)


def _validate_raw_triplet(item: dict) -> tuple[dict | None, str | None]:
    subject = (item.get("subject") or "").strip()
    relation = item.get("relation") or ""
    obj = (item.get("object") or "").strip()

    if relation not in RELATION_WHITELIST:
        return None, f"relation '{relation}' not in whitelist"
    if not subject or subject.lower() in VAGUE_TERMS:
        return None, f"vague/empty subject: '{subject}'"
    if not obj or obj.lower() in VAGUE_TERMS:
        return None, f"vague/empty object: '{obj}'"
    return {"subject": subject, "relation": relation, "object": obj}, None


def _dedup_triplets(triplets: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict] = []
    for t in triplets:
        key = (t["subject"].lower(), t["relation"], t["object"].lower())
        if key not in seen:
            seen.add(key)
            result.append(t)
    return result


def _build_extract_prompt(demos: list[tuple], target_report_text: str) -> str:
    relations_str = json.dumps(sorted(RELATION_WHITELIST))
    prompt = EXTRACT_SYSTEM_PROMPT.format(relations=relations_str)
    prompt += f"\n\nHere are {len(demos)} example reports with their correct triplets:\n"
    for i, (_, adv_id, gold_raw, report_text, score) in enumerate(demos, 1):
        gold = json.loads(gold_raw)
        prompt += f"\n---EXAMPLE {i} (advisory={adv_id}, similarity={score:.3f})---\n"
        prompt += f"REPORT:\n{report_text}\n\n"
        prompt += f"TRIPLETS:\n{json.dumps(gold, indent=2)}\n"
    prompt += f"\n---TARGET REPORT---\nREPORT:\n{target_report_text}\n\nTRIPLETS (JSON array):"
    return prompt


def run_extract_triplets(
    advisory_ids: list[str] | None = None,
    commit: bool = False,
    model: str = "gpt-4o",
) -> dict[str, Any]:
    """
    Extract triplets from advisory reports via kNN ICL + GPT-4o.

    Args:
        advisory_ids: see module docstring convention.
        commit: If True, write rows to ``extracted_triplets``. Default dry-run.
        model: OpenAI chat model.

    Returns:
        {run_id, processed, triplets_written, tokens_in, tokens_out,
         dry_run, elapsed_sec}
    """
    run_id = uuid4().hex[:12]
    started = perf_counter()

    if advisory_ids is not None and not advisory_ids:
        return _skip_result(run_id, "empty_advisory_ids", started, commit)

    sf = _get_snowflake_service()
    client = _get_openai_client() if commit else None

    where = [
        "a.report_embedding IS NOT NULL",
        "NOT EXISTS (SELECT 1 FROM extracted_triplets e WHERE e.advisory_id = a.advisory_id)",
    ]
    params: list[Any] = []
    if advisory_ids:
        placeholders = ",".join(["%s"] * len(advisory_ids))
        where.append(f"a.advisory_id IN ({placeholders})")
        params.extend(advisory_ids)

    total_in = 0
    total_out = 0
    total_triplets = 0
    processed = 0

    with sf.cursor() as cur:
        cur.execute(
            f"SELECT a.advisory_id FROM advisories a WHERE {' AND '.join(where)} "
            f"ORDER BY a.advisory_id",
            params,
        )
        to_process = [r[0] for r in cur.fetchall()]

        logger.info(
            "triplet_extract_start run_id=%s target=%s model=%s dry_run=%s",
            run_id, len(to_process), model, not commit,
        )

        for advisory_id in to_process:
            processed += 1
            # kNN demos
            cur.execute("""
                SELECT d.demo_id, d.advisory_id, d.gold_triplets, d.report_text,
                       VECTOR_COSINE_SIMILARITY(d.demo_embedding, a.report_embedding) AS score
                FROM demonstration_pool d, advisories a
                WHERE a.advisory_id = %s
                  AND d.advisory_id != %s
                  AND d.demo_embedding IS NOT NULL
                  AND a.report_embedding IS NOT NULL
                ORDER BY score DESC
                LIMIT %s
            """, (advisory_id, advisory_id, TOP_K_DEMOS))
            demos = cur.fetchall()

            # Target report LISTAGG
            cur.execute("""
                SELECT LISTAGG(chunk_text, '\n\n') WITHIN GROUP (ORDER BY chunk_index)
                FROM advisory_chunks
                WHERE advisory_id = %s
            """, (advisory_id,))
            row = cur.fetchone()
            report_text = (row[0] if row and row[0] else "") or ""

            prompt = _build_extract_prompt(demos, report_text)
            logger.info(
                "triplet_extract_item run_id=%s advisory_id=%s demos=%s report_chars=%s",
                run_id, advisory_id, len(demos), len(report_text),
            )

            if not commit:
                continue

            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0,
                    max_tokens=4000,
                )
                raw_text = response.choices[0].message.content
                total_in += response.usage.prompt_tokens
                total_out += response.usage.completion_tokens
                _log_llm(cur, pipeline_stage="triplet_extraction", model=model,
                         usage=response.usage, advisory_id=advisory_id)
            except Exception as e:
                logger.error("triplet_extract_llm_fail advisory_id=%s error=%s", advisory_id, e)
                continue

            try:
                raw_triplets = _parse_llm_json_array(raw_text)
            except Exception as e:
                logger.error("triplet_extract_parse_fail advisory_id=%s error=%s", advisory_id, e)
                continue

            accepted: list[dict] = []
            rejected = 0
            for item in raw_triplets:
                validated, _ = _validate_raw_triplet(item)
                if validated is None:
                    rejected += 1
                else:
                    accepted.append(validated)
            deduped = _dedup_triplets(accepted)

            for i, t in enumerate(deduped):
                triplet_id = f"{advisory_id}_{i:04d}"
                cur.execute(
                    "INSERT INTO extracted_triplets (triplet_id, advisory_id, subject, relation, object) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (triplet_id, advisory_id, t["subject"], t["relation"], t["object"]),
                )
            total_triplets += len(deduped)
            logger.info(
                "triplet_extract_item_done run_id=%s advisory_id=%s raw=%s accepted=%s "
                "deduped=%s rejected=%s",
                run_id, advisory_id, len(raw_triplets), len(accepted), len(deduped), rejected,
            )

    elapsed = perf_counter() - started
    logger.info(
        "triplet_extract_summary run_id=%s processed=%s triplets=%s tokens_in=%s "
        "tokens_out=%s dry_run=%s elapsed_sec=%.3f",
        run_id, processed, total_triplets, total_in, total_out, not commit, elapsed,
    )
    return {
        "run_id": run_id,
        "processed": processed,
        "triplets_written": total_triplets,
        "tokens_in": total_in,
        "tokens_out": total_out,
        "dry_run": not commit,
        "elapsed_sec": elapsed,
    }


# ────────────────────────────────────────────────────────────────────────────
# Phase 2 — run_align_entities
# ────────────────────────────────────────────────────────────────────────────

def _gpt4o_classify_pair(client, name_a: str, name_b: str, model: str, cur=None):
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": ALIGN_PAIR_PROMPT},
                {"role": "user", "content": f'Entity A: "{name_a}"\nEntity B: "{name_b}"'},
            ],
            temperature=0,
            max_tokens=60,
            response_format={"type": "json_object"},
        )
        _log_llm(cur, pipeline_stage="entity_deduplication", model=model, usage=response.usage)
        parsed = json.loads(response.choices[0].message.content.strip())
        return parsed.get("same_entity", False), parsed.get("canonical_name")
    except Exception as e:
        logger.warning("align_pair_failed a=%s b=%s error=%s", name_a, name_b, e)
        return False, None


def run_align_entities(
    advisory_ids: list[str] | None = None,
    commit: bool = False,
    sim_threshold: float = DEFAULT_SIM_THRESHOLD,
    model: str = "gpt-4o",
    type_model: str = "gpt-4o-mini",
) -> dict[str, Any]:
    """
    Align canonical entities across ``extracted_triplets`` (global sweep).

    ``advisory_ids`` is used only as a trigger gate:
      * ``[]``        → skip (nothing new to align).
      * ``None``/non-empty → run the global pipeline (all entities in the table).

    Args:
        commit: If True, write to ``entity_aliases`` and UPDATE ``extracted_triplets``.
        sim_threshold: cosine-similarity threshold for candidate pairs.
    """
    run_id = uuid4().hex[:12]
    started = perf_counter()

    if advisory_ids is not None and not advisory_ids:
        return _skip_result(run_id, "empty_advisory_ids", started, commit)

    sf = _get_snowflake_service()
    client = _get_openai_client()

    with sf.cursor() as cur:
        # Collect all named entities.
        cur.execute("""
            SELECT DISTINCT subject AS entity FROM extracted_triplets
            UNION
            SELECT DISTINCT object  AS entity FROM extracted_triplets
        """)
        all_entities = sorted({r[0].strip() for r in cur.fetchall() if r[0] and r[0].strip()})
        named = [e for e in all_entities if _is_named_entity(e)]

        logger.info(
            "entity_align_start run_id=%s total=%s named=%s sim_threshold=%.2f dry_run=%s",
            run_id, len(all_entities), len(named), sim_threshold, not commit,
        )

        if len(named) < 2:
            return _skip_result(run_id, "too_few_named_entities", started, commit)

        # Classify entity type (pattern → LLM fallback).
        typed: list[tuple[str, str]] = []
        for name in named:
            etype = _pattern_classify_entity(name) or _llm_classify_entity(name, client, type_model, cur=cur)
            typed.append((name, etype))

        # Embed via Cortex.
        cur.execute(
            "CREATE OR REPLACE TEMPORARY TABLE entity_embed_temp "
            "(entity_name VARCHAR(500), entity_type VARCHAR(50), embedding VECTOR(FLOAT, 1024))"
        )
        placeholders = ", ".join("(%s, %s)" for _ in typed)
        values: list[Any] = [v for name, etype in typed for v in (name, etype)]
        cur.execute(
            f"INSERT INTO entity_embed_temp (entity_name, entity_type) VALUES {placeholders}",
            values,
        )
        cur.execute(
            "UPDATE entity_embed_temp "
            "SET embedding = SNOWFLAKE.CORTEX.EMBED_TEXT_1024(%s, entity_name)",
            (ENTITY_EMBED_MODEL,),
        )

        # Candidate pairs via cosine similarity.
        cur.execute("""
            SELECT a.entity_name, a.entity_type, b.entity_name, b.entity_type,
                   VECTOR_COSINE_SIMILARITY(a.embedding, b.embedding) AS score
            FROM entity_embed_temp a, entity_embed_temp b
            WHERE a.entity_name < b.entity_name
              AND VECTOR_COSINE_SIMILARITY(a.embedding, b.embedding) >= %s
            ORDER BY score DESC
        """, (sim_threshold,))
        candidate_pairs = cur.fetchall()
        logger.info(
            "entity_align_candidates run_id=%s pairs=%s", run_id, len(candidate_pairs),
        )

        approved: dict[str, tuple[str, str]] = {}
        for name_a, type_a, name_b, type_b, score in candidate_pairs:
            same, canonical = _gpt4o_classify_pair(client, name_a, name_b, model, cur=cur)
            if not same or not canonical:
                continue
            alias = name_b if canonical == name_a else name_a
            entity_type = type_a if canonical == name_a else type_b
            if alias not in approved:
                approved[alias] = (canonical, entity_type)

        logger.info("entity_align_approved run_id=%s mappings=%s", run_id, len(approved))

        subject_updated = 0
        object_updated = 0
        deleted = 0
        if commit and approved:
            for alias, (canonical, entity_type) in approved.items():
                cur.execute("""
                    MERGE INTO entity_aliases AS t
                    USING (SELECT %s AS alias_name, %s AS canonical_name, %s AS entity_type) AS s
                    ON t.alias_name = s.alias_name
                    WHEN MATCHED THEN UPDATE SET canonical_name = s.canonical_name, entity_type = s.entity_type
                    WHEN NOT MATCHED THEN INSERT (alias_name, canonical_name, entity_type) VALUES (s.alias_name, s.canonical_name, s.entity_type)
                """, (alias, canonical, entity_type))

            cur.execute("""
                UPDATE extracted_triplets t
                SET subject = ea.canonical_name
                FROM entity_aliases ea
                WHERE LOWER(t.subject) = LOWER(ea.alias_name)
            """)
            subject_updated = cur.rowcount

            cur.execute("""
                UPDATE extracted_triplets t
                SET object = ea.canonical_name
                FROM entity_aliases ea
                WHERE LOWER(t.object) = LOWER(ea.alias_name)
            """)
            object_updated = cur.rowcount

            cur.execute("""
                DELETE FROM extracted_triplets
                WHERE triplet_id NOT IN (
                    SELECT MIN(triplet_id)
                    FROM extracted_triplets
                    GROUP BY advisory_id, subject, relation, object
                )
            """)
            deleted = cur.rowcount

    elapsed = perf_counter() - started
    logger.info(
        "entity_align_summary run_id=%s pairs=%s approved=%s subject_updated=%s "
        "object_updated=%s duplicates_deleted=%s dry_run=%s elapsed_sec=%.3f",
        run_id, len(candidate_pairs), len(approved), subject_updated, object_updated,
        deleted, not commit, elapsed,
    )
    return {
        "run_id": run_id,
        "candidate_pairs": len(candidate_pairs),
        "approved": len(approved),
        "subject_updated": subject_updated,
        "object_updated": object_updated,
        "duplicates_deleted": deleted,
        "dry_run": not commit,
        "elapsed_sec": elapsed,
    }


# ────────────────────────────────────────────────────────────────────────────
# Phase 4 — run_load_neo4j
# ────────────────────────────────────────────────────────────────────────────

def _ensure_neo4j_constraints(session) -> None:
    for label in ("Actor", "Malware", "Technique", "Tactic", "Campaign", "Other"):
        session.run(
            f"CREATE CONSTRAINT {label.lower()}_name IF NOT EXISTS "
            f"FOR (n:{label}) REQUIRE n.name IS UNIQUE"
        )


def _merge_neo4j_node(session, name: str, entity_type: str) -> None:
    if entity_type == "cve":
        if not session.run("MATCH (n:CVE {id: $id}) RETURN n LIMIT 1", id=name).single():
            session.run(
                "MERGE (n:Other {name: $name}) SET n.entity_type = $type",
                name=name, type=entity_type,
            )
    elif entity_type == "cwe":
        if not session.run("MATCH (n:CWE {id: $id}) RETURN n LIMIT 1", id=name).single():
            session.run(
                "MERGE (n:Other {name: $name}) SET n.entity_type = $type",
                name=name, type=entity_type,
            )
    else:
        label = LABEL_MAP.get(entity_type, "Other")
        session.run(
            f"MERGE (n:{label} {{name: $name}}) SET n.entity_type = $type",
            name=name, type=entity_type,
        )


def _merge_neo4j_edge(session, subject: str, subject_type: str,
                     obj: str, obj_type: str,
                     rel_label: str, advisory_id: str) -> None:
    if subject_type == "cve":
        s_match = "MATCH (s:CVE {id: $subject})"
    elif subject_type == "cwe":
        s_match = "MATCH (s:CWE {id: $subject})"
    else:
        s_label = LABEL_MAP.get(subject_type, "Other")
        s_match = f"MATCH (s:{s_label} {{name: $subject}})"

    if obj_type == "cve":
        o_match = "MATCH (o:CVE {id: $obj})"
    elif obj_type == "cwe":
        o_match = "MATCH (o:CWE {id: $obj})"
    else:
        o_label = LABEL_MAP.get(obj_type, "Other")
        o_match = f"MATCH (o:{o_label} {{name: $obj}})"

    session.run(
        f"""
        {s_match}
        {o_match}
        MERGE (s)-[r:{rel_label} {{advisory_id: $advisory_id}}]->(o)
        SET r.is_inferred = false
        """,
        subject=subject, obj=obj, advisory_id=advisory_id,
    )


def run_load_neo4j(
    advisory_ids: list[str] | None = None,
    commit: bool = False,
    type_model: str = "gpt-4o-mini",
) -> dict[str, Any]:
    """
    Load triplets from ``extracted_triplets`` into Neo4j.

    Args:
        advisory_ids: see module docstring convention. When non-empty, only
            those advisories are loaded; already-loaded ones are skipped.
        commit: If True, MERGE nodes + edges into Neo4j.
        type_model: OpenAI model for entity-type fallback classification.
    """
    run_id = uuid4().hex[:12]
    started = perf_counter()

    if advisory_ids is not None and not advisory_ids:
        return _skip_result(run_id, "empty_advisory_ids", started, commit)

    sf = _get_snowflake_service()
    driver = _get_neo4j_driver()
    client = _get_openai_client()

    with sf.cursor() as cur:
        if advisory_ids:
            placeholders = ",".join(["%s"] * len(advisory_ids))
            cur.execute(
                f"SELECT DISTINCT advisory_id FROM extracted_triplets "
                f"WHERE advisory_id IN ({placeholders}) ORDER BY advisory_id",
                advisory_ids,
            )
        else:
            cur.execute("SELECT DISTINCT advisory_id FROM extracted_triplets ORDER BY advisory_id")
        target_advisories = [r[0] for r in cur.fetchall()]

    # Skip advisories already materialised in Neo4j (idempotent re-runs).
    with driver.session() as session:
        result = session.run(
            "MATCH ()-[r]->() WHERE r.advisory_id IS NOT NULL "
            "RETURN DISTINCT r.advisory_id AS aid"
        )
        already_loaded = {rec["aid"] for rec in result}

    todo = [a for a in target_advisories if a not in already_loaded]
    logger.info(
        "triplet_load_start run_id=%s candidates=%s already_loaded=%s todo=%s dry_run=%s",
        run_id, len(target_advisories), len(already_loaded), len(todo), not commit,
    )

    total_edges = 0
    total_triplets = 0

    for advisory_id in todo:
        with sf.cursor() as cur:
            cur.execute(
                "SELECT subject, relation, object FROM extracted_triplets WHERE advisory_id = %s",
                (advisory_id,),
            )
            triplets = cur.fetchall()
        if not triplets:
            continue
        total_triplets += len(triplets)

        entities = set()
        for subject, _, obj in triplets:
            entities.add(subject.strip())
            entities.add(obj.strip())

        entity_types: dict[str, str] = {}
        with sf.cursor() as cur:
            for name in entities:
                etype = _pattern_classify_entity(name) or _llm_classify_entity(
                    name, client, type_model, cur=cur
                )
                entity_types[name] = etype

        if not commit:
            logger.info(
                "triplet_load_item_dry run_id=%s advisory_id=%s triplets=%s entities=%s",
                run_id, advisory_id, len(triplets), len(entities),
            )
            continue

        written = 0
        with driver.session() as session:
            _ensure_neo4j_constraints(session)
            for name, etype in entity_types.items():
                _merge_neo4j_node(session, name, etype)
            for subject, relation, obj in triplets:
                subject = subject.strip()
                obj = obj.strip()
                s_type = entity_types.get(subject, "other")
                o_type = entity_types.get(obj, "other")
                rel_label = RELATION_MAP.get(relation, relation.upper())
                try:
                    _merge_neo4j_edge(session, subject, s_type, obj, o_type, rel_label, advisory_id)
                    written += 1
                except Exception as e:
                    logger.warning(
                        "triplet_load_edge_fail advisory_id=%s s=%s rel=%s o=%s error=%s",
                        advisory_id, subject, rel_label, obj, e,
                    )
        total_edges += written
        logger.info(
            "triplet_load_item run_id=%s advisory_id=%s triplets=%s edges=%s",
            run_id, advisory_id, len(triplets), written,
        )

    elapsed = perf_counter() - started
    logger.info(
        "triplet_load_summary run_id=%s processed=%s triplets=%s edges=%s "
        "dry_run=%s elapsed_sec=%.3f",
        run_id, len(todo), total_triplets, total_edges, not commit, elapsed,
    )
    return {
        "run_id": run_id,
        "candidates": len(target_advisories),
        "already_loaded": len(already_loaded),
        "processed": len(todo),
        "triplets": total_triplets,
        "edges_written": total_edges,
        "dry_run": not commit,
        "elapsed_sec": elapsed,
    }


# ────────────────────────────────────────────────────────────────────────────
# Phase 3 — run_infer_relations
# ────────────────────────────────────────────────────────────────────────────

def _build_components(node_ids: Iterable, edges: list) -> dict:
    parent = {n: n for n in node_ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    for s_id, o_id in edges:
        union(s_id, o_id)

    components: dict[Any, list] = {}
    for n in parent:
        root = find(n)
        components.setdefault(root, []).append(n)
    return components


def _get_advisory_graph(session, advisory_id: str) -> list[dict]:
    r = session.run("""
        MATCH (s)-[r]->(o)
        WHERE r.advisory_id = $aid AND r.is_inferred = false
        RETURN
            elementId(s) AS s_eid, coalesce(s.name, s.id) AS s_name,
            labels(s) AS s_labels,
            elementId(o) AS o_eid, coalesce(o.name, o.id) AS o_name,
            labels(o) AS o_labels,
            type(r) AS rel_type
    """, aid=advisory_id)
    return r.data()


def _find_topic_and_centrals(edges_data: list[dict]) -> tuple[str, dict, list]:
    node_info: dict[str, dict] = {}
    for row in edges_data:
        node_info[row["s_eid"]] = {"name": row["s_name"], "labels": row["s_labels"]}
        node_info[row["o_eid"]] = {"name": row["o_name"], "labels": row["o_labels"]}

    edges = [(row["s_eid"], row["o_eid"]) for row in edges_data]
    components = _build_components(node_info.keys(), edges)

    degrees: dict[str, int] = {}
    out_degrees: dict[str, int] = {}
    subject_counts: dict[str, int] = {}
    for row in edges_data:
        s = row["s_eid"]
        o = row["o_eid"]
        degrees[s] = degrees.get(s, 0) + 1
        degrees[o] = degrees.get(o, 0) + 1
        out_degrees[s] = out_degrees.get(s, 0) + 1
        subject_counts[s] = subject_counts.get(s, 0) + 1

    def _rank(eid: str):
        return (degrees.get(eid, 0), out_degrees.get(eid, 0), subject_counts.get(eid, 0))

    centrals = [max(members, key=_rank) for members in components.values()]
    topic = max(centrals, key=_rank)
    return topic, node_info, [c for c in centrals if c != topic]


def _infer_relation(client, entity_a: str, entity_b: str, report_text: str, model: str, cur=None):
    user_prompt = (
        f"Report content:\n{report_text[:12000]}\n\n"
        f"Entity A: {entity_a}\n"
        f"Entity B: {entity_b}\n\n"
        "What is the relationship between Entity A and Entity B based on this report?"
    )
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": INFER_RELATION_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=100,
        )
        _log_llm(cur, pipeline_stage="relation_inference", model=model, usage=response.usage)
        raw = response.choices[0].message.content.strip()
        if raw.lower() in ("null", ""):
            return None
        parsed = json.loads(raw)
        if parsed.get("relation") not in RELATION_WHITELIST:
            return None
        return parsed
    except Exception as e:
        logger.warning("infer_relation_failed a=%s b=%s error=%s", entity_a, entity_b, e)
        return None


def _validate_inference(client, subject: str, relation: str, obj: str,
                       model: str, cur=None) -> bool:
    user_prompt = f'Subject: "{subject}"\nRelation: "{relation}"\nObject: "{obj}"'
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": VALIDATE_INFERENCE_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=20,
        )
        _log_llm(cur, pipeline_stage="relation_inference", model=model, usage=response.usage)
        parsed = json.loads(response.choices[0].message.content.strip())
        return bool(parsed.get("valid", False))
    except Exception as e:
        logger.warning("validate_inference_failed s=%s r=%s o=%s error=%s", subject, relation, obj, e)
        return False


def _get_report_text(cur, advisory_id: str) -> str:
    cur.execute("""
        SELECT LISTAGG(chunk_text, '\n\n') WITHIN GROUP (ORDER BY chunk_index)
        FROM advisory_chunks
        WHERE advisory_id = %s
    """, (advisory_id,))
    row = cur.fetchone()
    return row[0] if row and row[0] else ""


def run_infer_relations(
    advisory_ids: list[str] | None = None,
    commit: bool = False,
    model: str = "gpt-4o",
    validate_model: str = "gpt-4o-mini",
) -> dict[str, Any]:
    """
    For advisories whose Neo4j subgraph has disconnected components, ask GPT-4o
    to infer a relation between the topic entity and each other component's
    central entity. Validated edges are MERGEd into Neo4j with
    ``is_inferred = true``.

    Args:
        advisory_ids: see module docstring convention.
        commit: If True, write inferred edges to Neo4j.
    """
    run_id = uuid4().hex[:12]
    started = perf_counter()

    if advisory_ids is not None and not advisory_ids:
        return _skip_result(run_id, "empty_advisory_ids", started, commit)

    sf = _get_snowflake_service()
    driver = _get_neo4j_driver()
    client = _get_openai_client()

    # Determine target advisories from Neo4j.
    with driver.session() as session:
        if advisory_ids:
            result = session.run(
                "MATCH ()-[r]->() WHERE r.advisory_id IN $ids "
                "RETURN DISTINCT r.advisory_id AS aid ORDER BY aid",
                ids=advisory_ids,
            )
        else:
            result = session.run(
                "MATCH ()-[r]->() WHERE r.advisory_id IS NOT NULL "
                "RETURN DISTINCT r.advisory_id AS aid ORDER BY aid"
            )
        candidate_ids = [rec["aid"] for rec in result]

    logger.info(
        "triplet_infer_start run_id=%s candidates=%s model=%s dry_run=%s",
        run_id, len(candidate_ids), model, not commit,
    )

    processed = 0
    attempted = 0
    succeeded = 0

    with sf.cursor() as cur:
        for advisory_id in candidate_ids:
            with driver.session() as session:
                edges_data = _get_advisory_graph(session, advisory_id)
            if not edges_data:
                continue

            edges = [(r["s_eid"], r["o_eid"]) for r in edges_data]
            node_ids = list({r["s_eid"] for r in edges_data} | {r["o_eid"] for r in edges_data})
            if len(_build_components(node_ids, edges)) <= 1:
                continue

            topic, node_info, others = _find_topic_and_centrals(edges_data)
            topic_name = node_info[topic]["name"]
            topic_label = node_info[topic]["labels"][0] if node_info[topic]["labels"] else "Other"
            report_text = _get_report_text(cur, advisory_id)
            processed += 1

            for candidate_eid in others:
                attempted += 1
                candidate_name = node_info[candidate_eid]["name"]
                candidate_labels = node_info[candidate_eid]["labels"]
                candidate_label = candidate_labels[0] if candidate_labels else "Other"

                result = _infer_relation(
                    client, candidate_name, topic_name, report_text, model, cur=cur,
                )
                if result is None:
                    continue
                subj = result["subject"]
                rel = result["relation"]
                obj = result["object"]
                rel_label = RELATION_MAP[rel]

                if not _validate_inference(client, subj, rel, obj, validate_model, cur=cur):
                    continue

                if subj == topic_name:
                    s_name, s_label = topic_name, topic_label
                    o_name, o_label = candidate_name, candidate_label
                else:
                    s_name, s_label = candidate_name, candidate_label
                    o_name, o_label = topic_name, topic_label

                succeeded += 1
                if commit:
                    with driver.session() as session:
                        if s_label == "CVE":
                            s_match = "MATCH (s:CVE {id: $subject})"
                        elif s_label == "CWE":
                            s_match = "MATCH (s:CWE {id: $subject})"
                        else:
                            s_match = f"MATCH (s:{s_label} {{name: $subject}})"
                        if o_label == "CVE":
                            o_match = "MATCH (o:CVE {id: $obj})"
                        elif o_label == "CWE":
                            o_match = "MATCH (o:CWE {id: $obj})"
                        else:
                            o_match = f"MATCH (o:{o_label} {{name: $obj}})"
                        session.run(
                            f"""
                            {s_match}
                            {o_match}
                            MERGE (s)-[r:{rel_label} {{advisory_id: $advisory_id}}]->(o)
                            SET r.is_inferred = true
                            """,
                            subject=s_name, obj=o_name, advisory_id=advisory_id,
                        )

    elapsed = perf_counter() - started
    logger.info(
        "triplet_infer_summary run_id=%s candidates=%s processed=%s attempted=%s "
        "succeeded=%s dry_run=%s elapsed_sec=%.3f",
        run_id, len(candidate_ids), processed, attempted, succeeded, not commit, elapsed,
    )
    return {
        "run_id": run_id,
        "candidates": len(candidate_ids),
        "processed": processed,
        "attempted": attempted,
        "succeeded": succeeded,
        "dry_run": not commit,
        "elapsed_sec": elapsed,
    }
