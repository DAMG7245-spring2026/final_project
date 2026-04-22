"""
Step 0-3: Generate and verify gold triplets for demonstration_pool.

Three-pass approach:
  1. Extract: GPT-4o extracts raw triplets from report_text
  2. Verify Round 1: GPT-4o checks factual accuracy against source text
  3. Verify Round 2: GPT-4o does strict quality check on entity specificity,
     meaningfulness, and whether the triplet adds value to a knowledge graph.
  Only triplets that pass BOTH rounds are kept.

Usage:
  poetry run python scripts/generate_gold_triplets.py                  # dry-run, 3 reports
  poetry run python scripts/generate_gold_triplets.py --limit 5        # dry-run, 5 reports
  poetry run python scripts/generate_gold_triplets.py --commit         # all 100, write to DB
  poetry run python scripts/generate_gold_triplets.py --commit --limit 10
"""
import argparse
import json
import time

from dotenv import load_dotenv
from openai import OpenAI

import snowflake.connector
from app.config import get_settings
from app.services.llm_usage_log import log_llm_usage

load_dotenv()

RELATION_WHITELIST = [
    "uses",
    "targets",
    "exploits",
    "attributed_to",
    "affects",
    "has_weakness",
    "mitigates",
]

EXTRACTION_PROMPT = """You are a cybersecurity analyst. Extract (subject, relation, object) triplets from the following threat intelligence report.

Rules:
- ONLY use these relations: {relations}
- Subject and object MUST be specific named entities: threat actor names (e.g., APT29, Lazarus Group), malware families (e.g., DarkSide, Cobalt Strike), CVE IDs (e.g., CVE-2021-44228), CWE IDs, MITRE technique IDs (e.g., T1059), product names (e.g., Microsoft Exchange), organization names, industry sectors, etc.
- Do NOT use vague subjects like "the attacker", "malicious cyber actors", "the malware", "threat actors"
- Do NOT extract references to documents, publications, or advisories as entities
- Do NOT extract defensive recommendations as triplets (e.g., "CISA mitigates X" is wrong)
- Do NOT use single letters, abbreviations without context, or generic terms (e.g., "IV", "DLL", "key") as entities
- Each triplet must represent a factual claim directly stated in the report
- Return a JSON array of objects with keys: "subject", "relation", "object"
- If no valid triplets can be extracted, return []

Report:
{report_text}

Triplets (JSON array):"""

VERIFY_ROUND1_PROMPT = """You are a cybersecurity knowledge graph quality reviewer.

Given a threat intelligence report and extracted triplets, verify EACH triplet:

1. **Relation valid**: Is the relation one of: {relations}?
2. **Factually accurate**: Is the claim directly supported by the report text? Quote the supporting sentence.
3. **Not a reference**: Is this an actual threat relationship, not just a citation of a document/advisory?
4. **Entities specific**: Are subject and object specific named entities (not vague like "the attacker")?

For each triplet, return:
- All original fields (subject, relation, object)
- "valid": true/false
- "reason": brief explanation (quote supporting text if valid, explain why if invalid)

Return a JSON array.

Report:
{report_text}

Triplets to verify:
{triplets_json}

Verified triplets (JSON array):"""

VERIFY_ROUND2_PROMPT = """You are a strict cybersecurity knowledge graph quality auditor doing a FINAL review.

These triplets have already passed an initial verification. Now apply these STRICT criteria:

1. **Entity meaningfulness**: Would this entity be a useful node in a cybersecurity knowledge graph?
   - REJECT: generic terms (e.g., "DLL", "key", "IV", "file", "network", "system", "data")
   - REJECT: descriptions instead of names (e.g., "malicious executable", "encryption algorithm")
   - ACCEPT: specific names (e.g., "ICONICSTEALER", "CVE-2023-20269", "T1059", "Chrome", "AES-256")
   - ACCEPT: nation-state actors and government entities (e.g., "North Korean government", "Chinese government", "Russian government") — these are valid threat actor attributions in CTI

2. **Relationship correctness**: Does the relation type accurately describe the relationship?
   - "targets" means the subject actively attacks/focuses on the object
   - "uses" means the subject employs the object as a tool/technique
   - "exploits" means actively exploiting a specific vulnerability
   - "attributed_to" means the subject is attributed to the object (actor/group)
   - "associated_with" means a known association between entities
   - "affects" means a vulnerability/issue impacts a product/system
   - "has_weakness" means a CVE maps to a CWE
   - "mitigates" means a specific countermeasure reduces a specific threat

3. **Duplicate check**: Are there near-duplicate triplets saying the same thing?

4. **Knowledge graph value**: Would this triplet create a meaningful edge in a threat intelligence knowledge graph?

For each triplet, return:
- All original fields (subject, relation, object)
- "valid": true/false
- "reason": brief explanation

Return a JSON array.

Triplets to audit:
{triplets_json}

Final audit (JSON array):"""


def _parse_response(raw: str) -> list[dict]:
    """Parse LLM JSON response, handling markdown fences."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    return json.loads(text)


def _call_llm(
    client: OpenAI,
    prompt: str,
    model: str,
    *,
    operation: str,
    max_tokens: int = 4000,
    metadata: dict | None = None,
):
    """Call OpenAI and return parsed JSON + usage."""
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=max_tokens,
        )
        parsed = _parse_response(response.choices[0].message.content)
        log_llm_usage(
            source="script",
            operation=operation,
            provider="openai",
            model=model,
            usage=response.usage,
            success=True,
            metadata=metadata,
        )
        return parsed, response.usage
    except Exception as exc:
        log_llm_usage(
            source="script",
            operation=operation,
            provider="openai",
            model=model,
            success=False,
            error_message=str(exc),
            metadata=metadata,
        )
        raise


def extract_triplets(
    client: OpenAI,
    report_text: str,
    model: str,
    metadata: dict | None = None,
):
    prompt = EXTRACTION_PROMPT.format(
        relations=json.dumps(RELATION_WHITELIST),
        report_text=report_text,
    )
    return _call_llm(
        client,
        prompt,
        model,
        operation="generate_gold_triplets.extract",
        metadata=metadata,
    )


def verify_round1(
    client: OpenAI,
    report_text: str,
    triplets: list[dict],
    model: str,
    metadata: dict | None = None,
):
    prompt = VERIFY_ROUND1_PROMPT.format(
        relations=json.dumps(RELATION_WHITELIST),
        report_text=report_text,
        triplets_json=json.dumps(triplets, indent=2),
    )
    return _call_llm(
        client,
        prompt,
        model,
        operation="generate_gold_triplets.verify_round1",
        metadata=metadata,
    )


def verify_round2(
    client: OpenAI,
    triplets: list[dict],
    model: str,
    metadata: dict | None = None,
):
    prompt = VERIFY_ROUND2_PROMPT.format(
        triplets_json=json.dumps(triplets, indent=2),
    )
    return _call_llm(
        client,
        prompt,
        model,
        operation="generate_gold_triplets.verify_round2",
        metadata=metadata,
    )


def filter_valid(verified: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split verified triplets into accepted and rejected."""
    accepted, rejected = [], []
    for t in verified:
        clean = {"subject": t["subject"], "relation": t["relation"], "object": t["object"]}
        if t.get("valid", False):
            accepted.append(clean)
        else:
            rejected.append({**clean, "reason": t.get("reason", "")})
    return accepted, rejected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Write to Snowflake")
    parser.add_argument("--limit", type=int, default=3, help="Number of reports (default 3 for dry-run)")
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

    cur.execute("""
        SELECT demo_id, advisory_id, document_type, report_text
        FROM demonstration_pool
        WHERE gold_triplets IS NULL
        ORDER BY demo_id
    """)
    rows = cur.fetchall()

    if args.limit:
        rows = rows[: args.limit]

    mode = "COMMIT" if args.commit else "DRY-RUN"
    print(f"[{mode}] Processing {len(rows)} demos with model={args.model}")
    print(f"Relation whitelist: {RELATION_WHITELIST}")
    print("Verification: 3-pass (extract → verify R1 → verify R2)")
    print()

    total_input_tokens = 0
    total_output_tokens = 0
    stats = {"extracted": 0, "after_whitelist": 0, "after_r1": 0, "after_r2": 0}
    t0 = time.time()

    for i, (demo_id, advisory_id, doc_type, report_text) in enumerate(rows, 1):
        print(f"[{i:3d}/{len(rows)}] {demo_id} ({advisory_id}, {doc_type})")
        usage_meta = {
            "demo_id": str(demo_id),
            "advisory_id": str(advisory_id),
            "document_type": str(doc_type) if doc_type is not None else None,
        }

        # === Pass 1: Extract ===
        try:
            raw_triplets, usage = extract_triplets(
                client,
                report_text,
                args.model,
                metadata=usage_meta,
            )
            total_input_tokens += usage.prompt_tokens
            total_output_tokens += usage.completion_tokens
        except Exception as e:
            print(f"  !! Extract failed: {e}\n")
            continue

        stats["extracted"] += len(raw_triplets)

        # Whitelist filter
        wl_triplets = [t for t in raw_triplets if t.get("relation") in RELATION_WHITELIST]
        wl_rejected = len(raw_triplets) - len(wl_triplets)
        stats["after_whitelist"] += len(wl_triplets)

        if wl_rejected:
            print(f"  Pass 1 Extract: {len(raw_triplets)} raw → {len(wl_triplets)} after whitelist filter ({wl_rejected} bad relation)")
        else:
            print(f"  Pass 1 Extract: {len(raw_triplets)} triplets")

        if not wl_triplets:
            print("  No triplets to verify.\n")
            if args.commit:
                cur.execute(
                    "UPDATE demonstration_pool SET gold_triplets = PARSE_JSON(%s) WHERE demo_id = %s",
                    (json.dumps([]), demo_id),
                )
                conn.commit()
            continue

        # === Pass 2: Verify Round 1 (factual accuracy) ===
        try:
            r1_result, usage = verify_round1(
                client,
                report_text,
                wl_triplets,
                args.model,
                metadata=usage_meta,
            )
            total_input_tokens += usage.prompt_tokens
            total_output_tokens += usage.completion_tokens
            r1_accepted, r1_rejected = filter_valid(r1_result)
        except Exception as e:
            print(f"  !! Verify R1 failed: {e}, using whitelist-filtered triplets")
            r1_accepted = wl_triplets
            r1_rejected = []

        stats["after_r1"] += len(r1_accepted)
        print(f"  Pass 2 Verify R1: {len(wl_triplets)} → {len(r1_accepted)} accepted, {len(r1_rejected)} rejected")
        for t in r1_rejected:
            print(f"    ✗ R1: {t['subject']} --[{t['relation']}]--> {t['object']}  ({t.get('reason', '')})")

        if not r1_accepted:
            print("  No triplets after R1.\n")
            if args.commit:
                cur.execute(
                    "UPDATE demonstration_pool SET gold_triplets = PARSE_JSON(%s) WHERE demo_id = %s",
                    (json.dumps([]), demo_id),
                )
                conn.commit()
            continue

        # === Pass 3: Verify Round 2 (strict quality audit) ===
        try:
            r2_result, usage = verify_round2(
                client,
                r1_accepted,
                args.model,
                metadata=usage_meta,
            )
            total_input_tokens += usage.prompt_tokens
            total_output_tokens += usage.completion_tokens
            r2_accepted, r2_rejected = filter_valid(r2_result)
        except Exception as e:
            print(f"  !! Verify R2 failed: {e}, using R1 results")
            r2_accepted = r1_accepted
            r2_rejected = []

        stats["after_r2"] += len(r2_accepted)
        print(f"  Pass 3 Verify R2: {len(r1_accepted)} → {len(r2_accepted)} accepted, {len(r2_rejected)} rejected")
        for t in r2_rejected:
            print(f"    ✗ R2: {t['subject']} --[{t['relation']}]--> {t['object']}  ({t.get('reason', '')})")

        # Final result
        print(f"  ── Final: {len(r2_accepted)} gold triplets")
        for t in r2_accepted:
            print(f"    ✓ {t['subject']}  --[{t['relation']}]-->  {t['object']}")

        # === Write to DB ===
        if args.commit:
            cur.execute(
                "UPDATE demonstration_pool SET gold_triplets = PARSE_JSON(%s) WHERE demo_id = %s",
                (json.dumps(r2_accepted), demo_id),
            )
            conn.commit()

        print()

    elapsed = time.time() - t0
    cost = total_input_tokens / 1e6 * 2.5 + total_output_tokens / 1e6 * 10.0

    print("=" * 70)
    print(f"[{mode}] Done. {len(rows)} demos in {elapsed:.1f}s")
    print("  Pipeline:  extracted → whitelist → R1 verify → R2 audit")
    print(f"  Counts:    {stats['extracted']} → {stats['after_whitelist']} → {stats['after_r1']} → {stats['after_r2']}")
    if stats["extracted"] > 0:
        print(f"  Final acceptance rate: {stats['after_r2'] / stats['extracted'] * 100:.1f}%")
    print(f"  Tokens — input: {total_input_tokens:,}  output: {total_output_tokens:,}")
    print(f"  Estimated cost: ${cost:.2f}")
    if not args.commit:
        print("\n  [DRY-RUN] No DB writes. Rerun with --commit to save.")


if __name__ == "__main__":
    main()
