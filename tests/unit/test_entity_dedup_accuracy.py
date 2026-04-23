"""Entity deduplication accuracy test.

Gold-pair method: 24 labeled CTI entity pairs (12 same, 12 different).
Calls gpt4o_classify_pair() and measures accuracy.
Pass criterion: accuracy >= 0.75
"""
import pytest
from openai import OpenAI
from app.config import get_settings
from scripts.align_entities import gpt4o_classify_pair


# ── Gold pairs ────────────────────────────────────────────────────────────────
# (entity_a, entity_b, is_same_entity)

GOLD_PAIRS: list[tuple[str, str, bool]] = [
    # ── Same entity (aliases / spelling variants) ──────────────────────────
    ("APT28",          "Fancy Bear",          True),
    ("APT29",          "Cozy Bear",           True),
    ("Lazarus Group",  "Lazarus",             True),
    ("Lazarus Group",  "HIDDEN COBRA",        True),
    ("REvil",          "Sodinokibi",          True),
    ("BlackCat",       "ALPHV",               True),
    ("WannaCry",       "WannaCrypt",          True),
    ("LockBit",        "LockBit ransomware",  True),
    ("Cobalt Strike",  "CobaltStrike",        True),
    ("Emotet",         "Heodo",               True),
    ("Conti",          "Conti ransomware",    True),
    ("TrickBot",       "Trickbot",            True),

    # ── Different entities ─────────────────────────────────────────────────
    ("APT28",          "APT29",               False),
    ("Lazarus Group",  "APT28",               False),
    ("WannaCry",       "NotPetya",            False),
    ("Cobalt Strike",  "Metasploit",          False),
    ("LockBit",        "REvil",               False),
    ("BlackCat",       "Conti",               False),
    ("Emotet",         "TrickBot",            False),
    ("APT41",          "Lazarus Group",       False),
    ("Volt Typhoon",   "Salt Typhoon",        False),
    ("CVE-2021-44228", "CVE-2021-34527",      False),
    ("Mimikatz",       "BloodHound",          False),
    ("DarkSide",       "LockBit",             False),
]

ACCURACY_THRESHOLD = 0.75


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def openai_client():
    settings = get_settings()
    return OpenAI(api_key=settings.openai_api_key)


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestEntityDedupAccuracy:

    def test_gold_pair_count(self):
        same    = [p for p in GOLD_PAIRS if p[2] is True]
        diff    = [p for p in GOLD_PAIRS if p[2] is False]
        assert len(same) == 12, "Expected 12 same-entity pairs"
        assert len(diff) == 12, "Expected 12 different-entity pairs"

    @pytest.mark.parametrize("entity_a,entity_b,expected", GOLD_PAIRS)
    def test_single_pair(self, openai_client, entity_a, entity_b, expected):
        same, _, _usage = gpt4o_classify_pair(entity_a, entity_b, openai_client, "gpt-4o")
        assert same == expected, (
            f"'{entity_a}' ↔ '{entity_b}': expected same={expected}, got same={same}"
        )

    def test_overall_accuracy_meets_threshold(self, openai_client):
        correct = 0
        results = []

        for entity_a, entity_b, expected in GOLD_PAIRS:
            same, canonical, _usage = gpt4o_classify_pair(entity_a, entity_b, openai_client, "gpt-4o")
            passed = same == expected
            correct += int(passed)
            results.append({
                "entity_a": entity_a,
                "entity_b": entity_b,
                "expected": expected,
                "predicted": same,
                "canonical": canonical,
                "correct": passed,
            })

        accuracy = correct / len(GOLD_PAIRS)

        # Print breakdown for debugging
        print(f"\n{'='*60}")
        print(f"Entity Deduplication Accuracy Report")
        print(f"{'='*60}")
        for r in results:
            status = "✓" if r["correct"] else "✗"
            print(f"  {status}  '{r['entity_a']}' ↔ '{r['entity_b']}'")
            print(f"     expected={r['expected']}  predicted={r['predicted']}  canonical={r['canonical']}")
        print(f"{'='*60}")
        print(f"  Correct : {correct} / {len(GOLD_PAIRS)}")
        print(f"  Accuracy: {accuracy:.2%}  (threshold: {ACCURACY_THRESHOLD:.0%})")
        print(f"{'='*60}\n")

        assert accuracy >= ACCURACY_THRESHOLD, (
            f"Deduplication accuracy {accuracy:.2%} is below threshold {ACCURACY_THRESHOLD:.0%} "
            f"({correct}/{len(GOLD_PAIRS)} correct)"
        )
