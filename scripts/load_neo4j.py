"""
Phase 4: Load extracted triplets from Snowflake into Neo4j.

For each advisory:
  1. Read triplets from extracted_triplets
  2. Classify entity_type (regex → GPT-4o-mini fallback)
  3. MERGE Entity nodes (skip for CVE/CWE → use existing nodes)
  4. MERGE relationship edges {advisory_id, is_inferred: false}

Usage:
  poetry run python scripts/load_neo4j.py                        # dry-run, aa24-207a only
  poetry run python scripts/load_neo4j.py --advisory aa23-165a   # dry-run, specific advisory
  poetry run python scripts/load_neo4j.py --commit               # write aa24-207a to Neo4j
  poetry run python scripts/load_neo4j.py --commit --all         # write all 302 advisories
"""
import argparse
import json
import re

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector
from neo4j import GraphDatabase
from openai import OpenAI

from app.config import get_settings

# ── Constants ─────────────────────────────────────────────────────────────────

RELATION_MAP = {
    "uses": "USES",
    "targets": "TARGETS",
    "exploits": "EXPLOITS",
    "attributed_to": "ATTRIBUTED_TO",
    "affects": "AFFECTS",
    "has_weakness": "HAS_WEAKNESS",
    "mitigates": "MITIGATES",
}

ENTITY_TYPES = {"cve", "cwe", "technique", "tactic", "actor", "software", "campaign", "other"}

LABEL_MAP = {
    "actor": "Actor",
    "software": "Malware",
    "technique": "Technique",
    "tactic": "Tactic",
    "campaign": "Campaign",
    "other": "Other",
}

CLASSIFY_PROMPT = """You are a cybersecurity knowledge graph expert.
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

CVE_RE    = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)
CWE_RE    = re.compile(r'^CWE-\d+$', re.IGNORECASE)
TECH_RE   = re.compile(r'^T\d{4}(\.\d{3})?$', re.IGNORECASE)
TACTIC_RE = re.compile(r'^TA\d{4}$', re.IGNORECASE)

DEFAULT_ADVISORY = "aa24-207a"


# ── Entity type classification ────────────────────────────────────────────────

def pattern_classify(name: str) -> str | None:
    if CVE_RE.match(name):
        return "cve"
    if CWE_RE.match(name):
        return "cwe"
    if TACTIC_RE.match(name):
        return "tactic"
    if TECH_RE.match(name):
        return "technique"
    return None


def llm_classify(name: str, client: OpenAI) -> str:
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": CLASSIFY_PROMPT},
                {"role": "user", "content": f'Entity name: "{name}"'},
            ],
            temperature=0,
            max_tokens=30,
        )
        raw = response.choices[0].message.content.strip()
        parsed = json.loads(raw)
        entity_type = parsed.get("entity_type", "other")
        return entity_type if entity_type in ENTITY_TYPES else "other"
    except Exception:
        return "other"


def classify_entities(entities: list[str], client: OpenAI) -> dict[str, str]:
    result = {}
    for name in entities:
        entity_type = pattern_classify(name)
        if entity_type:
            result[name] = entity_type
        else:
            result[name] = llm_classify(name, client)
    return result


# ── Neo4j helpers ─────────────────────────────────────────────────────────────

def ensure_constraint(session):
    for label in ["Actor", "Malware", "Technique", "Tactic", "Campaign", "Other"]:
        session.run(
            f"CREATE CONSTRAINT {label.lower()}_name IF NOT EXISTS "
            f"FOR (n:{label}) REQUIRE n.name IS UNIQUE"
        )


def merge_node(session, name: str, entity_type: str, commit: bool):
    if not commit:
        return
    if entity_type == "cve":
        result = session.run("MATCH (n:CVE {id: $id}) RETURN n", id=name).single()
        if not result:
            print(f"    ⚠ CVE not found in Neo4j: {name}, creating Other fallback")
            session.run("MERGE (n:Other {name: $name}) SET n.entity_type = $type", name=name, type=entity_type)
    elif entity_type == "cwe":
        result = session.run("MATCH (n:CWE {id: $id}) RETURN n", id=name).single()
        if not result:
            print(f"    ⚠ CWE not found in Neo4j: {name}, creating Other fallback")
            session.run("MERGE (n:Other {name: $name}) SET n.entity_type = $type", name=name, type=entity_type)
    else:
        label = LABEL_MAP.get(entity_type, "Other")
        session.run(f"MERGE (n:{label} {{name: $name}}) SET n.entity_type = $type", name=name, type=entity_type)


def merge_edge(session, subject: str, subject_type: str,
               obj: str, obj_type: str,
               rel_label: str, advisory_id: str, commit: bool):
    if not commit:
        return

    # Resolve subject node
    if subject_type == "cve":
        s_match = "MATCH (s:CVE {id: $subject})"
    elif subject_type == "cwe":
        s_match = "MATCH (s:CWE {id: $subject})"
    else:
        s_label = LABEL_MAP.get(subject_type, "Other")
        s_match = f"MATCH (s:{s_label} {{name: $subject}})"

    # Resolve object node
    if obj_type == "cve":
        o_match = "MATCH (o:CVE {id: $obj})"
    elif obj_type == "cwe":
        o_match = "MATCH (o:CWE {id: $obj})"
    else:
        o_label = LABEL_MAP.get(obj_type, "Other")
        o_match = f"MATCH (o:{o_label} {{name: $obj}})"

    query = f"""
        {s_match}
        {o_match}
        MERGE (s)-[r:{rel_label} {{advisory_id: $advisory_id}}]->(o)
        SET r.is_inferred = false
    """
    session.run(query, subject=subject, obj=obj, advisory_id=advisory_id)


# ── Main ──────────────────────────────────────────────────────────────────────

def process_advisory(advisory_id: str, cur, neo4j_session, client: OpenAI, commit: bool):
    print(f"\n[{'COMMIT' if commit else 'DRY-RUN'}] {advisory_id}")

    cur.execute(
        "SELECT subject, relation, object FROM extracted_triplets WHERE advisory_id = %s",
        (advisory_id,)
    )
    triplets = cur.fetchall()
    if not triplets:
        print("  No triplets found, skipping.")
        return 0

    print(f"  Triplets: {len(triplets)}")

    # Collect unique entities
    entities = set()
    for subject, _, obj in triplets:
        entities.add(subject.strip())
        entities.add(obj.strip())

    # Classify entity types
    print(f"  Classifying {len(entities)} unique entities...")
    entity_types = classify_entities(list(entities), client)

    type_counts: dict[str, int] = {}
    for t in entity_types.values():
        type_counts[t] = type_counts.get(t, 0) + 1
    print(f"  Types: {type_counts}")

    if not commit:
        print("  [DRY-RUN] Skipping Neo4j writes.")
        for subject, relation, obj in triplets[:3]:
            s_type = entity_types.get(subject.strip(), "other")
            o_type = entity_types.get(obj.strip(), "other")
            rel_label = RELATION_MAP.get(relation, relation.upper())
            print(f"    ({subject} [{s_type}]) -[:{rel_label}]-> ({obj} [{o_type}])")
        if len(triplets) > 3:
            print(f"    ... and {len(triplets) - 3} more")
        return len(triplets)

    # MERGE nodes
    ensure_constraint(neo4j_session)
    for name, entity_type in entity_types.items():
        merge_node(neo4j_session, name, entity_type, commit)

    # MERGE edges
    written = 0
    for subject, relation, obj in triplets:
        subject = subject.strip()
        obj = obj.strip()
        s_type = entity_types.get(subject, "other")
        o_type = entity_types.get(obj, "other")
        rel_label = RELATION_MAP.get(relation, relation.upper())
        try:
            merge_edge(neo4j_session, subject, s_type, obj, o_type, rel_label, advisory_id, commit)
            written += 1
        except Exception as e:
            print(f"    !! Edge failed: {subject} -[{rel_label}]-> {obj}: {e}")

    print(f"  Written: {written} edges")
    return written


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Write to Neo4j (default: dry-run)")
    parser.add_argument("--advisory", default=DEFAULT_ADVISORY, help="Single advisory ID to process")
    parser.add_argument("--all", action="store_true", help="Process all advisories")
    args = parser.parse_args()

    s = get_settings()

    conn = snowflake.connector.connect(
        account=s.snowflake_account,
        user=s.snowflake_user,
        password=s.snowflake_password,
        database=s.snowflake_database,
        schema=s.snowflake_schema,
        warehouse=s.snowflake_warehouse,
    )
    cur = conn.cursor()
    client = OpenAI(api_key=s.openai_api_key)
    driver = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_username, s.neo4j_password))

    if args.all:
        cur.execute("SELECT DISTINCT advisory_id FROM extracted_triplets ORDER BY advisory_id")
        advisory_ids = [r[0] for r in cur.fetchall()]
    else:
        advisory_ids = [args.advisory]

    # Skip already-loaded advisories
    if args.commit and args.all:
        with driver.session() as session:
            r = session.run("MATCH ()-[r]->() WHERE r.advisory_id IS NOT NULL RETURN DISTINCT r.advisory_id AS aid")
            already_loaded = {rec["aid"] for rec in r}
        advisory_ids = [a for a in advisory_ids if a not in already_loaded]
        print(f"Skipping {len(already_loaded)} already-loaded advisories")

    print(f"Processing {len(advisory_ids)} advisory/advisories")

    total_edges = 0
    for advisory_id in advisory_ids:
        try:
            with driver.session() as session:
                total_edges += process_advisory(advisory_id, cur, session, client, args.commit)
        except Exception as e:
            print(f"  !! Advisory {advisory_id} failed: {e}, skipping")

    print(f"\n{'='*60}")
    print(f"Done. Total edges written: {total_edges}")

    conn.close()
    driver.close()


if __name__ == "__main__":
    main()
