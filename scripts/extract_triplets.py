"""
Phase 1 Step 1-3: Extract triplets from all advisories using kNN ICL + GPT-4o.

For each advisory:
  1. kNN → find top-4 similar demos from demonstration_pool
  2. Build ICL prompt (4 demos + target report)
  3. GPT-4o → raw triplets
  4. Pydantic validation + whitelist filter + exact-match dedup
  5. Write to extracted_triplets

Usage:
  poetry run python scripts/extract_triplets.py                    # dry-run, 1 advisory
  poetry run python scripts/extract_triplets.py --limit 5         # dry-run, 5 advisories
  poetry run python scripts/extract_triplets.py --commit          # all 302, write to DB
  poetry run python scripts/extract_triplets.py --commit --limit 10
"""
import argparse
import json
import time
import uuid

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector
from openai import OpenAI
from pydantic import BaseModel, field_validator

from app.config import get_settings
from app.token_logger import log_llm_call

# ── Constants ────────────────────────────────────────────────────────────────

RELATION_WHITELIST = {
    "uses", "targets", "exploits", "attributed_to",
    "affects", "has_weakness", "mitigates",
}

VAGUE_TERMS = {
    "the attacker", "the attackers", "attacker", "attackers",
    "malicious actors", "malicious cyber actors", "threat actors",
    "the threat actor", "threat actor", "the malware", "malware",
    "cyber actors", "the group", "the adversary", "adversary",
    "apt actors", "apt actor", "the actor", "actor",
}

TOP_K_DEMOS = 4

SYSTEM_PROMPT = """You are a cybersecurity analyst. Extract (subject, relation, object) triplets from the threat intelligence report provided.

Rules:
- ONLY use these relations: {relations}
- Subject and object MUST be specific named entities: threat actor names (e.g. APT29, Lazarus Group), malware families (e.g. DarkSide, Cobalt Strike), CVE IDs (e.g. CVE-2021-44228), CWE IDs, MITRE technique IDs (e.g. T1059), product names (e.g. Microsoft Exchange), organization names, industry sectors, etc.
- Do NOT use vague subjects/objects like "the attacker", "malicious actors", "threat actors", "the malware"
- Do NOT extract defensive recommendations as triplets
- Each triplet must represent a factual claim directly stated in the report
- Return a JSON array of objects with keys: "subject", "relation", "object"
- If no valid triplets can be extracted, return []"""


# ── Pydantic model ────────────────────────────────────────────────────────────

class Triplet(BaseModel):
    subject: str
    relation: str
    object: str

    @field_validator("relation")
    @classmethod
    def relation_in_whitelist(cls, v):
        if v not in RELATION_WHITELIST:
            raise ValueError(f"relation '{v}' not in whitelist")
        return v

    @field_validator("subject", "object")
    @classmethod
    def not_empty_or_vague(cls, v):
        if not v.strip():
            raise ValueError("empty entity")
        if v.lower().strip() in VAGUE_TERMS:
            raise ValueError(f"vague entity: '{v}'")
        return v.strip()


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_llm_response(raw: str) -> list[dict]:
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    return json.loads(text)


def validate_triplets(raw: list[dict]) -> tuple[list[Triplet], list[dict]]:
    accepted, rejected = [], []
    for item in raw:
        try:
            t = Triplet(**item)
            accepted.append(t)
        except Exception as e:
            rejected.append({**item, "reason": str(e)})
    return accepted, rejected


def dedup(triplets: list[Triplet]) -> list[Triplet]:
    seen = set()
    result = []
    for t in triplets:
        key = (t.subject.lower(), t.relation, t.object.lower())
        if key not in seen:
            seen.add(key)
            result.append(t)
    return result


def build_prompt(demos: list[tuple], target_report_text: str) -> str:
    relations_str = json.dumps(sorted(RELATION_WHITELIST))
    prompt = SYSTEM_PROMPT.format(relations=relations_str)
    prompt += f"\n\nHere are {len(demos)} example reports with their correct triplets:\n"

    for i, (demo_id, adv_id, gold_raw, report_text, score) in enumerate(demos, 1):
        gold = json.loads(gold_raw)
        prompt += f"\n---EXAMPLE {i} (advisory={adv_id}, similarity={score:.3f})---\n"
        prompt += f"REPORT:\n{report_text}\n\n"
        prompt += f"TRIPLETS:\n{json.dumps(gold, indent=2)}\n"

    prompt += f"\n---TARGET REPORT---\nREPORT:\n{target_report_text}\n\nTRIPLETS (JSON array):"
    return prompt


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Write to Snowflake (default: dry-run)")
    parser.add_argument("--limit", type=int, default=1, help="Number of advisories to process (default 1)")
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model")
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

    # Get advisories not yet extracted
    cur.execute("""
        SELECT a.advisory_id
        FROM advisories a
        WHERE a.report_embedding IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM extracted_triplets e
              WHERE e.advisory_id = a.advisory_id
          )
        ORDER BY a.advisory_id
    """)
    all_ids = [r[0] for r in cur.fetchall()]
    to_process = all_ids[:args.limit]

    mode = "COMMIT" if args.commit else "DRY-RUN"
    print(f"[{mode}] {len(to_process)} advisories to process (model={args.model})")
    print(f"Relation whitelist: {sorted(RELATION_WHITELIST)}")
    print()

    total_input_tokens = 0
    total_output_tokens = 0
    total_triplets = 0
    t0 = time.time()

    for idx, advisory_id in enumerate(to_process, 1):
        print(f"[{idx}/{len(to_process)}] {advisory_id}")

        # Step B: kNN top-4 demos
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
        print(f"  Top-{len(demos)} demos: " + ", ".join(
            f"{d[1]}({d[4]:.3f})" for d in demos
        ))

        # Step C: get target report_text
        cur.execute("""
            SELECT LISTAGG(chunk_text, '\n\n') WITHIN GROUP (ORDER BY chunk_index)
            FROM advisory_chunks
            WHERE advisory_id = %s
        """, (advisory_id,))
        report_text = cur.fetchone()[0] or ""

        # Step D: build prompt + call LLM
        prompt = build_prompt(demos, report_text)
        print(f"  Prompt: ~{len(prompt)//4:,} tokens")

        if not args.commit:
            print(f"  [DRY-RUN] Skipping LLM call.\n")
            continue

        try:
            response = client.chat.completions.create(
                model=args.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=4000,
            )
            raw_text = response.choices[0].message.content
            total_input_tokens += response.usage.prompt_tokens
            total_output_tokens += response.usage.completion_tokens
            log_llm_call(
                pipeline_stage="triplet_extraction",
                model=args.model,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                advisory_id=advisory_id,
                cur=cur,
            )
        except Exception as e:
            print(f"  !! LLM call failed: {e}\n")
            continue

        # Step E: parse JSON
        try:
            raw_triplets = parse_llm_response(raw_text)
        except Exception as e:
            print(f"  !! JSON parse failed: {e}\n")
            continue

        print(f"  Raw triplets: {len(raw_triplets)}")

        # Step F: Pydantic validation
        accepted, rejected = validate_triplets(raw_triplets)
        print(f"  After validation: {len(accepted)} accepted, {len(rejected)} rejected")
        for r in rejected:
            print(f"    ✗ {r.get('subject')} --[{r.get('relation')}]--> {r.get('object')}  ({r.get('reason')})")

        # Step G: exact match dedup
        deduped = dedup(accepted)
        dupes = len(accepted) - len(deduped)
        if dupes:
            print(f"  After dedup: {len(deduped)} (-{dupes} duplicates)")

        # Step H: write to DB
        print(f"  ── Final: {len(deduped)} triplets")
        for t in deduped:
            print(f"    ✓ {t.subject}  --[{t.relation}]-->  {t.object}")

        total_triplets += len(deduped)

        for i, t in enumerate(deduped):
            triplet_id = f"{advisory_id}_{i:04d}"
            cur.execute("""
                INSERT INTO extracted_triplets (triplet_id, advisory_id, subject, relation, object)
                VALUES (%s, %s, %s, %s, %s)
            """, (triplet_id, advisory_id, t.subject, t.relation, t.object))
        conn.commit()
        print()

    elapsed = time.time() - t0
    cost = total_input_tokens / 1e6 * 2.5 + total_output_tokens / 1e6 * 10.0

    print("=" * 70)
    print(f"[{mode}] Done. {len(to_process)} advisories in {elapsed:.1f}s")
    if args.commit:
        print(f"  Total triplets extracted: {total_triplets}")
        print(f"  Tokens — input: {total_input_tokens:,}  output: {total_output_tokens:,}")
        print(f"  Estimated cost: ${cost:.2f}")

    conn.close()


if __name__ == "__main__":
    main()
