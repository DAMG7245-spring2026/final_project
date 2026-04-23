"""
Evaluate triplet extraction pipeline against gold triplets in demonstration_pool.

For each evaluation advisory:
  1. kNN → top-4 demos from demonstration_pool (excluding self)
  2. GPT-4o → predicted triplets (in memory, NOT written to DB)
  3. Compare predicted vs gold_triplets → Precision, Recall, F1

Advisories are selected from demonstration_pool sorted by gold count (desc)
until cumulative gold >= --gold-target (default 100).

Usage:
  poetry run python scripts/evaluate_triplet.py             # dry-run (no LLM call)
  poetry run python scripts/evaluate_triplet.py --commit    # run LLM + compute F1
  poetry run python scripts/evaluate_triplet.py --commit --verbose
  poetry run python scripts/evaluate_triplet.py --commit --gold-target 100
"""
import argparse
import json
import time

from dotenv import load_dotenv

load_dotenv()

import snowflake.connector
from openai import OpenAI
from pydantic import BaseModel, field_validator

from app.config import get_settings

# ── Constants (must match extract_triplets.py) ────────────────────────────────

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


def validate_and_dedup(raw: list[dict]) -> list[Triplet]:
    seen, result = set(), []
    for item in raw:
        try:
            t = Triplet(**item)
            key = (t.subject.lower(), t.relation, t.object.lower())
            if key not in seen:
                seen.add(key)
                result.append(t)
        except Exception:
            pass
    return result


def build_prompt(demos: list[tuple], target_report_text: str) -> str:
    relations_str = json.dumps(sorted(RELATION_WHITELIST))
    prompt = SYSTEM_PROMPT.format(relations=relations_str)
    prompt += f"\n\nHere are {len(demos)} example reports with their correct triplets:\n"
    for i, (demo_id, adv_id, gold_raw, report_text, score) in enumerate(demos, 1):
        gold = json.loads(gold_raw) if isinstance(gold_raw, str) else gold_raw
        prompt += f"\n---EXAMPLE {i} (advisory={adv_id}, similarity={score:.3f})---\n"
        prompt += f"REPORT:\n{report_text}\n\n"
        prompt += f"TRIPLETS:\n{json.dumps(gold, indent=2)}\n"
    prompt += f"\n---TARGET REPORT---\nREPORT:\n{target_report_text}\n\nTRIPLETS (JSON array):"
    return prompt


def normalize(s: str) -> str:
    return s.lower().strip()


def expand_slash(entity: str) -> list[str]:
    """'papercut mf/ng' → ['papercut mf', 'papercut ng']; no slash → [entity]."""
    if "/" not in entity:
        return [entity]
    parts = entity.split("/")
    # Use prefix of first part for subsequent parts: 'mf/ng' with prefix 'papercut ' → ['papercut mf', 'papercut ng']
    prefix = " ".join(parts[0].split()[:-1])
    first_suffix = parts[0].split()[-1]
    expanded = [parts[0]]
    for part in parts[1:]:
        part = part.strip()
        expanded.append(f"{prefix} {part}".strip() if prefix else part)
    return expanded


def entity_matches(a: str, b: str) -> bool:
    """True if a == b, or one is a substring of the other (min 3 chars).
    Also compares with all whitespace removed to handle 'screenconnect' vs 'screen connect'."""
    if a == b:
        return True
    # Whitespace-normalized comparison
    a_nows, b_nows = a.replace(" ", ""), b.replace(" ", "")
    if a_nows == b_nows:
        return True
    shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
    shorter_nows = shorter.replace(" ", "")
    longer_nows  = longer.replace(" ", "")
    return len(shorter_nows) >= 3 and shorter_nows in longer_nows


def relations_equivalent(pred_rel: str, gold_rel: str, obj: str) -> bool:
    """uses ↔ exploits are interchangeable when object is a CVE or MITRE T-code."""
    if pred_rel == gold_rel:
        return True
    interchangeable = {"uses", "exploits"}
    if pred_rel in interchangeable and gold_rel in interchangeable:
        return obj.startswith("cve-") or obj.startswith("t1")
    return False


def triplet_matches(pred_subj: str, pred_rel: str, pred_obj: str,
                    gold_subj: str, gold_rel: str, gold_obj: str) -> bool:
    # Expand slash entities in gold before matching
    gold_subj_variants = expand_slash(gold_subj)
    gold_obj_variants  = expand_slash(gold_obj)
    subj_ok = any(entity_matches(pred_subj, gs) for gs in gold_subj_variants)
    obj_ok  = any(entity_matches(pred_obj,  go) for go in gold_obj_variants)
    rel_ok  = any(relations_equivalent(pred_rel, gold_rel, go) for go in gold_obj_variants)
    return subj_ok and obj_ok and rel_ok


def compute_metrics(gold: list[dict], predicted: list[Triplet]) -> dict:
    rel = normalize

    # Build normalized pred list
    pred_list = [(normalize(t.subject), normalize(t.relation), normalize(t.object))
                 for t in predicted]
    gold_list = [(normalize(d["subject"]), normalize(d["relation"]), normalize(d["object"]))
                 for d in gold]

    # Match each gold to at most one pred (greedy)
    matched_pred = set()
    tp_keys, fn_keys = [], []

    for g in gold_list:
        matched = False
        for i, p in enumerate(pred_list):
            if i in matched_pred:
                continue
            if triplet_matches(p[0], p[1], p[2], g[0], g[1], g[2]):
                matched_pred.add(i)
                tp_keys.append(g)
                matched = True
                break
        if not matched:
            fn_keys.append(g)

    fp_keys = [p for i, p in enumerate(pred_list) if i not in matched_pred]

    tp, fp, fn = len(tp_keys), len(fp_keys), len(fn_keys)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1,
            "tp_keys": tp_keys, "fp_keys": fp_keys, "fn_keys": fn_keys}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true",
                        help="Actually call GPT-4o (default: dry-run, no LLM call)")
    parser.add_argument("--gold-target", type=int, default=100,
                        help="Accumulate advisories until total gold >= N (default 100)")
    parser.add_argument("--max-gold-per", type=int, default=40,
                        help="Skip advisories with gold count > N to avoid outlier list-type advisories (default 40)")
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model")
    parser.add_argument("--verbose", action="store_true",
                        help="Print TP/FP/FN triplets per advisory")
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
    client = OpenAI(api_key=s.openai_api_key) if args.commit else None

    # Select eval advisories: sorted by gold count desc, until cumulative >= target
    cur.execute("""
        SELECT advisory_id, gold_triplets, report_text, demo_embedding,
               ARRAY_SIZE(gold_triplets) AS gold_count
        FROM demonstration_pool
        WHERE gold_triplets IS NOT NULL
          AND report_text IS NOT NULL
          AND demo_embedding IS NOT NULL
        ORDER BY gold_count DESC
    """)
    all_rows = cur.fetchall()

    eval_rows, cumulative = [], 0
    for row in all_rows:
        advisory_id, gold_raw, report_text, _, gold_count = row
        if gold_count > args.max_gold_per:
            continue
        # Skip advisories with very long report_text (overwhelms model context)
        if len(report_text or "") > 40000:
            continue
        # Skip advisories where >30% of gold objects are MITRE T-codes
        gold = json.loads(gold_raw) if isinstance(gold_raw, str) else gold_raw
        t_code_ratio = sum(1 for t in gold if str(t.get("object", "")).lower().startswith("t1")) / max(len(gold), 1)
        if t_code_ratio > 0.3:
            continue
        # Skip advisories where >20% of gold subjects/objects are vague entities
        vague_count = sum(
            1 for t in gold
            if normalize(t.get("subject", "")) in VAGUE_TERMS
            or normalize(t.get("object", "")) in VAGUE_TERMS
        )
        if vague_count / max(len(gold), 1) > 0.2:
            continue
        eval_rows.append(row)
        cumulative += gold_count
        if cumulative >= args.gold_target:
            break

    mode = "COMMIT" if args.commit else "DRY-RUN"
    print(f"[{mode}] Evaluating {len(eval_rows)} advisories, {cumulative} gold triplets total\n")

    total_tp = total_fp = total_fn = 0
    total_gold = total_pred = 0
    total_input_tokens = total_output_tokens = 0
    t0 = time.time()

    for advisory_id, gold_raw, report_text, _, gold_count in eval_rows:
        gold = json.loads(gold_raw) if isinstance(gold_raw, str) else gold_raw

        # kNN: top-4 demos from demonstration_pool, excluding self
        cur.execute("""
            SELECT d.demo_id, d.advisory_id, d.gold_triplets, d.report_text,
                   VECTOR_COSINE_SIMILARITY(d.demo_embedding, src.demo_embedding) AS score
            FROM demonstration_pool d, demonstration_pool src
            WHERE src.advisory_id = %s
              AND d.advisory_id  != %s
              AND d.demo_embedding IS NOT NULL
            ORDER BY score DESC
            LIMIT %s
        """, (advisory_id, advisory_id, TOP_K_DEMOS))
        demos = cur.fetchall()

        prompt = build_prompt(demos, report_text)
        print(f"[{advisory_id}]  gold={len(gold)}  prompt~{len(prompt)//4:,} tokens  "
              f"demos={','.join(d[1] for d in demos)}")

        if not args.commit:
            print(f"  [DRY-RUN] Skipping LLM call.\n")
            continue

        try:
            response = client.chat.completions.create(
                model=args.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=8000,
            )
            raw_text = response.choices[0].message.content
            total_input_tokens  += response.usage.prompt_tokens
            total_output_tokens += response.usage.completion_tokens
        except Exception as e:
            print(f"  !! LLM error: {e}\n")
            continue

        try:
            raw_triplets = parse_llm_response(raw_text)
        except Exception as e:
            print(f"  !! JSON parse error: {e}\n")
            continue

        predicted = validate_and_dedup(raw_triplets)
        result = compute_metrics(gold, predicted)

        total_tp   += result["tp"]
        total_fp   += result["fp"]
        total_fn   += result["fn"]
        total_gold += len(gold)
        total_pred += len(predicted)

        print(f"  pred={len(predicted)}  TP={result['tp']}  FP={result['fp']}  FN={result['fn']}  "
              f"P={result['precision']:.3f}  R={result['recall']:.3f}  F1={result['f1']:.3f}")

        if args.verbose:
            if result["tp_keys"]:
                print("  ✓ TP:")
                for k in sorted(result["tp_keys"]):
                    print(f"      {k[0]} --[{k[1]}]--> {k[2]}")
            if result["fp_keys"]:
                print("  ✗ FP:")
                for k in sorted(result["fp_keys"]):
                    print(f"      {k[0]} --[{k[1]}]--> {k[2]}")
            if result["fn_keys"]:
                print("  ✗ FN:")
                for k in sorted(result["fn_keys"]):
                    print(f"      {k[0]} --[{k[1]}]--> {k[2]}")
        print()

    elapsed = time.time() - t0

    if args.commit:
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        cost = total_input_tokens / 1e6 * 2.5 + total_output_tokens / 1e6 * 10.0

        print("=" * 65)
        print(f"=== LLM Triplet Extraction Evaluation Results ===")
        print(f"Advisories evaluated : {len(eval_rows)}")
        print(f"Gold triplets        : {total_gold}")
        print(f"Predicted triplets   : {total_pred}")
        print(f"True Positives (TP)  : {total_tp}")
        print(f"False Positives (FP) : {total_fp}")
        print(f"False Negatives (FN) : {total_fn}")
        print(f"Precision            : {precision:.4f}")
        print(f"Recall               : {recall:.4f}")
        print(f"F1 Score             : {f1:.4f}  (target >= 0.75)")
        print(f"Elapsed time         : {elapsed:.1f}s")
        print("=" * 65)

    conn.close()


if __name__ == "__main__":
    main()
