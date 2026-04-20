"""
Phase 2 Step 2-2: Collect unique entity names from extracted_triplets and classify entity type.

Classification order (per entity):
  1. Regex pattern match  → cve / cwe / technique / tactic
  2. GPT-4o-mini          → actor / software / campaign / other (fallback)

Results are written to a local TSV file (entities.tsv) for inspection.

Usage:
  poetry run python scripts/collect_entities.py              # dry-run, print only
  poetry run python scripts/collect_entities.py --commit     # write entities.tsv
"""
import argparse
import json
import re

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector
from openai import OpenAI

from app.config import get_settings

# ── Constants ────────────────────────────────────────────────────────────────

ENTITY_TYPES = {"cve", "cwe", "technique", "tactic", "actor", "software", "campaign", "other"}

SYSTEM_PROMPT = """You are a cybersecurity knowledge graph expert.
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


# ── Pattern matching ──────────────────────────────────────────────────────────

CVE_RE    = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)
CWE_RE    = re.compile(r'^CWE-\d+$', re.IGNORECASE)
TECH_RE   = re.compile(r'^T\d{4}(\.\d{3})?$', re.IGNORECASE)
TACTIC_RE = re.compile(r'^TA\d{4}$', re.IGNORECASE)


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


# ── LLM fallback ──────────────────────────────────────────────────────────────

def llm_classify(name: str, client: OpenAI, model: str) -> str:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f'Entity name: "{name}"'},
            ],
            temperature=0,
            max_tokens=30,
        )
        raw = response.choices[0].message.content.strip()
        parsed = json.loads(raw)
        entity_type = parsed.get("entity_type", "other")
        return entity_type if entity_type in ENTITY_TYPES else "other"
    except Exception as e:
        print(f"  !! LLM classify failed for '{name}': {e}")
        return "other"


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Write entities.tsv (default: print only)")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model for fallback classification")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of entities to process (0 = all)")
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

    # Collect unique entity names
    cur.execute("""
        SELECT DISTINCT subject AS entity FROM extracted_triplets
        UNION
        SELECT DISTINCT object  AS entity FROM extracted_triplets
    """)
    all_entities = sorted({row[0].strip() for row in cur.fetchall() if row[0] and row[0].strip()})
    if args.limit:
        all_entities = all_entities[:args.limit]
    print(f"Total unique entity names: {len(all_entities)}")

    # Classify each entity
    results: list[tuple[str, str]] = []
    stats = {"pattern": 0, "llm": 0}

    for i, name in enumerate(all_entities, 1):
        entity_type = pattern_classify(name)
        if entity_type:
            stats["pattern"] += 1
        else:
            entity_type = llm_classify(name, client, args.model)
            stats["llm"] += 1
        results.append((name, entity_type))

        if i % 50 == 0 or i == len(all_entities):
            print(f"  [{i}/{len(all_entities)}] classified")

    # Summary
    print(f"\nClassification breakdown:")
    print(f"  Pattern match: {stats['pattern']}")
    print(f"  LLM fallback : {stats['llm']}")

    type_counts: dict[str, int] = {}
    for _, t in results:
        type_counts[t] = type_counts.get(t, 0) + 1
    print(f"\nEntity type distribution:")
    for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {t:12s}: {count}")

    if args.commit:
        out_path = "scripts/entities.tsv"
        with open(out_path, "w") as f:
            f.write("entity_name\tentity_type\n")
            for name, entity_type in results:
                f.write(f"{name}\t{entity_type}\n")
        print(f"\nWritten to {out_path}")
    else:
        print("\n[DRY-RUN] Use --commit to write entities.tsv")

    conn.close()


if __name__ == "__main__":
    main()
