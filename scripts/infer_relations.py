"""
Phase 3: Relation Inference for disconnected subgraphs.

For each advisory with multiple components:
  1. Find components using union-find
  2. Find central entity per component (highest degree)
  3. Find topic entity (highest degree among centrals)
  4. Build inference pairs (topic entity vs other centrals)
  5. GPT-4o infers relation using full report text as context
  6. MERGE inferred edges back to Neo4j (is_inferred=true)

Usage:
  poetry run python scripts/infer_relations.py                        # dry-run, all advisories
  poetry run python scripts/infer_relations.py --advisory aa20-283a   # dry-run, one advisory
  poetry run python scripts/infer_relations.py --commit               # write all to Neo4j
  poetry run python scripts/infer_relations.py --commit --advisory aa20-283a
"""
import argparse
import json

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector
from neo4j import GraphDatabase
from openai import OpenAI

from app.config import get_settings
from app.token_logger import log_llm_call

# ── Constants ─────────────────────────────────────────────────────────────────

RELATION_WHITELIST = {
    "uses", "targets", "exploits", "attributed_to",
    "affects", "has_weakness", "mitigates",
}

RELATION_MAP = {
    "uses": "USES", "targets": "TARGETS", "exploits": "EXPLOITS",
    "attributed_to": "ATTRIBUTED_TO", "affects": "AFFECTS",
    "has_weakness": "HAS_WEAKNESS", "mitigates": "MITIGATES",
}

LABEL_MAP = {
    "actor": "Actor", "software": "Malware", "technique": "Technique",
    "tactic": "Tactic", "campaign": "Campaign", "other": "Other",
    "cve": "CVE", "cwe": "CWE",
}

SYSTEM_PROMPT = """You are a cybersecurity analyst. Two entities appear in the same threat intelligence report.
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

VALIDATE_PROMPT = """You are a cybersecurity knowledge graph validator.
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


# ── Union-Find ────────────────────────────────────────────────────────────────

def build_components(node_ids: list, edges: list) -> dict:
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

    components: dict[str, list] = {}
    for n in node_ids:
        root = find(n)
        components.setdefault(root, []).append(n)

    return components


# ── Neo4j helpers ─────────────────────────────────────────────────────────────

def get_advisory_graph(session, advisory_id: str):
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


def get_node_degrees(edges_data: list) -> dict:
    degrees: dict[str, int] = {}
    for row in edges_data:
        s = row['s_eid']
        o = row['o_eid']
        degrees[s] = degrees.get(s, 0) + 1
        degrees[o] = degrees.get(o, 0) + 1
    return degrees


def get_node_subject_counts(edges_data: list) -> dict:
    counts: dict[str, int] = {}
    for row in edges_data:
        s = row['s_eid']
        counts[s] = counts.get(s, 0) + 1
    return counts


def find_central_entity(component_eids: list, degrees: dict, out_degrees: dict, subject_counts: dict) -> str:
    return max(
        component_eids,
        key=lambda n: (degrees.get(n, 0), out_degrees.get(n, 0), subject_counts.get(n, 0))
    )


def merge_inferred_edge(session, subject_name: str, subject_label: str,
                        obj_name: str, obj_label: str,
                        rel_label: str, advisory_id: str):
    if subject_label == "CVE":
        s_match = "MATCH (s:CVE {id: $subject})"
    elif subject_label == "CWE":
        s_match = "MATCH (s:CWE {id: $subject})"
    else:
        s_match = f"MATCH (s:{subject_label} {{name: $subject}})"

    if obj_label == "CVE":
        o_match = "MATCH (o:CVE {id: $obj})"
    elif obj_label == "CWE":
        o_match = "MATCH (o:CWE {id: $obj})"
    else:
        o_match = f"MATCH (o:{obj_label} {{name: $obj}})"

    query = f"""
        {s_match}
        {o_match}
        MERGE (s)-[r:{rel_label} {{advisory_id: $advisory_id}}]->(o)
        SET r.is_inferred = true
    """
    session.run(query, subject=subject_name, obj=obj_name, advisory_id=advisory_id)


# ── Snowflake helpers ─────────────────────────────────────────────────────────

def get_report_text(cur, advisory_id: str) -> str:
    cur.execute("""
        SELECT LISTAGG(chunk_text, '\n\n') WITHIN GROUP (ORDER BY chunk_index)
        FROM advisory_chunks
        WHERE advisory_id = %s
    """, (advisory_id,))
    row = cur.fetchone()
    return row[0] if row and row[0] else ""


# ── LLM inference ─────────────────────────────────────────────────────────────

def infer_relation(client: OpenAI, entity_a: str, entity_b: str,
                   report_text: str, model: str = "gpt-4o") -> tuple[dict | None, object]:
    user_prompt = f"""Report content:
{report_text[:12000]}

Entity A: {entity_a}
Entity B: {entity_b}

What is the relationship between Entity A and Entity B based on this report?"""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=100,
        )
        raw = response.choices[0].message.content.strip()
        if raw.lower() == "null" or raw == "":
            return None, response.usage
        parsed = json.loads(raw)
        if parsed.get("relation") not in RELATION_WHITELIST:
            return None, response.usage
        return parsed, response.usage
    except Exception as e:
        print(f"    !! LLM error: {e}")
        return None, None


def validate_inference(client: OpenAI, subject: str, relation: str, obj: str,
                       model: str = "gpt-4o-mini") -> tuple[bool, object]:
    user_prompt = f'Subject: "{subject}"\nRelation: "{relation}"\nObject: "{obj}"'
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": VALIDATE_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=20,
        )
        raw = response.choices[0].message.content.strip()
        parsed = json.loads(raw)
        return bool(parsed.get("valid", False)), response.usage
    except Exception as e:
        print(f"    !! Validate error: {e}")
        return False, None


# ── Main logic per advisory ───────────────────────────────────────────────────

def process_advisory(advisory_id: str, session, cur, client: OpenAI,
                     commit: bool, model: str, sf_cur=None) -> tuple[int, int]:
    edges_data = get_advisory_graph(session, advisory_id)
    if not edges_data:
        return 0, 0

    # Build node lookup
    node_info: dict[str, dict] = {}
    for row in edges_data:
        node_info[row['s_eid']] = {'name': row['s_name'], 'labels': row['s_labels']}
        node_info[row['o_eid']] = {'name': row['o_name'], 'labels': row['o_labels']}

    node_ids = list(node_info.keys())
    edges = [(row['s_eid'], row['o_eid']) for row in edges_data]

    # Find components
    components = build_components(node_ids, edges)
    if len(components) <= 1:
        return 0, 0

    # Compute degrees
    degrees = get_node_degrees(edges_data)
    out_degrees = {row['s_eid']: out_degrees_count(row['s_eid'], edges_data)
                   for row in edges_data}
    subject_counts = get_node_subject_counts(edges_data)

    # Find central entity per component
    centrals = []
    for root, members in components.items():
        central = find_central_entity(members, degrees, out_degrees, subject_counts)
        centrals.append(central)

    # Find topic entity (highest degree among centrals)
    topic_eid = max(
        centrals,
        key=lambda n: (degrees.get(n, 0), out_degrees.get(n, 0), subject_counts.get(n, 0))
    )
    topic_info = node_info[topic_eid]
    topic_name = topic_info['name']
    topic_label = topic_info['labels'][0] if topic_info['labels'] else 'Other'

    print(f"  Components: {len(components)}, Topic entity: {topic_name} ({topic_label})")

    # Build inference pairs
    inference_pairs = [
        (node_info[c], c) for c in centrals if c != topic_eid
    ]

    # Get report text
    report_text = get_report_text(cur, advisory_id)

    attempted = len(inference_pairs)
    succeeded = 0

    for candidate_info, candidate_eid in inference_pairs:
        candidate_name = candidate_info['name']
        candidate_label = candidate_info['labels'][0] if candidate_info['labels'] else 'Other'

        result, infer_usage = infer_relation(client, candidate_name, topic_name, report_text, model)
        if infer_usage is not None:
            log_llm_call(
                pipeline_stage="relation_inference",
                model=model,
                prompt_tokens=infer_usage.prompt_tokens,
                completion_tokens=infer_usage.completion_tokens,
                advisory_id=advisory_id,
                cur=sf_cur,
            )

        if result is None:
            print(f"    ✗ ({candidate_name}, {topic_name}) → null")
            continue

        subj = result['subject']
        rel = result['relation']
        obj = result['object']
        rel_label = RELATION_MAP[rel]

        # Validate semantic correctness
        valid, validate_usage = validate_inference(client, subj, rel, obj, model="gpt-4o-mini")
        if validate_usage is not None:
            log_llm_call(
                pipeline_stage="relation_inference",
                model="gpt-4o-mini",
                prompt_tokens=validate_usage.prompt_tokens,
                completion_tokens=validate_usage.completion_tokens,
                advisory_id=advisory_id,
                cur=sf_cur,
            )
        if not valid:
            print(f"    ✗ ({subj}, {rel}, {obj}) → invalid semantics")
            continue

        # Determine which is subject/object in Neo4j
        if subj == topic_name:
            s_name, s_label = topic_name, topic_label
            o_name, o_label = candidate_name, candidate_label
        else:
            s_name, s_label = candidate_name, candidate_label
            o_name, o_label = topic_name, topic_label

        print(f"    ✓ {s_name} --[{rel_label}]--> {o_name} (is_inferred=true)")
        succeeded += 1

        if commit:
            merge_inferred_edge(session, s_name, s_label, o_name, o_label,
                                rel_label, advisory_id)

    return attempted, succeeded


def out_degrees_count(eid: str, edges_data: list) -> int:
    return sum(1 for row in edges_data if row['s_eid'] == eid)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Write to Neo4j (default: dry-run)")
    parser.add_argument("--advisory", default=None, help="Single advisory ID to process")
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model")
    args = parser.parse_args()

    s = get_settings()
    conn = snowflake.connector.connect(
        account=s.snowflake_account, user=s.snowflake_user,
        password=s.snowflake_password, database=s.snowflake_database,
        schema=s.snowflake_schema, warehouse=s.snowflake_warehouse,
    )
    cur = conn.cursor()
    client = OpenAI(api_key=s.openai_api_key)
    driver = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_username, s.neo4j_password))

    mode = "COMMIT" if args.commit else "DRY-RUN"
    print(f"[{mode}] Phase 3 Relation Inference (model={args.model})")

    total_attempted = 0
    total_succeeded = 0
    total_processed = 0

    with driver.session() as session:
        if args.advisory:
            advisory_ids = [args.advisory]
        else:
            r = session.run("MATCH ()-[r]->() WHERE r.advisory_id IS NOT NULL RETURN DISTINCT r.advisory_id AS aid ORDER BY aid")
            advisory_ids = [rec['aid'] for rec in r]

        for advisory_id in advisory_ids:
            edges_data = get_advisory_graph(session, advisory_id)
            if not edges_data:
                continue

            node_ids = list({row['s_eid'] for row in edges_data} | {row['o_eid'] for row in edges_data})
            edges = [(row['s_eid'], row['o_eid']) for row in edges_data]
            components = build_components(node_ids, edges)

            if len(components) <= 1:
                continue

            total_processed += 1
            print(f"\n[{mode}] {advisory_id}")

            attempted, succeeded = process_advisory(
                advisory_id, session, cur, client, args.commit, args.model, sf_cur=cur
            )
            total_attempted += attempted
            total_succeeded += succeeded

    print(f"\n{'='*60}")
    print(f"[{mode}] Done.")
    print(f"  Advisories with disconnected subgraphs: {total_processed}")
    print(f"  Inference pairs attempted: {total_attempted}")
    print(f"  Succeeded (non-null): {total_succeeded}")
    print(f"  Failed (null): {total_attempted - total_succeeded}")

    conn.close()
    driver.close()


if __name__ == "__main__":
    main()
