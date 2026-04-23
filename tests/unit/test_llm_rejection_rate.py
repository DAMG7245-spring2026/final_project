"""LLM output rejection rate test.

Calls GPT-4o with real CISA advisory excerpts using the same prompt as
extract_triplets.py, then measures: rejected / total < 0.15.
"""
import json
import pytest
from openai import OpenAI

from app.config import get_settings
from scripts.extract_triplets import (
    RELATION_WHITELIST,
    SYSTEM_PROMPT,
    parse_llm_response,
    validate_triplets,
)

REJECTION_THRESHOLD = 0.15

# ── Real CISA advisory excerpts (public domain) ───────────────────────────────

ADVISORY_TEXTS = [
    # 1. Akira ransomware (CISA AA23-284A)
    """
    Akira ransomware has impacted a wide range of businesses and critical infrastructure entities in North America,
    Europe, and Australia. Akira threat actors exploited CVE-2023-20269, a zero-day vulnerability in Cisco
    Adaptive Security Appliance (ASA) and Cisco Firepower Threat Defense (FTD) software. Additionally, Akira
    actors exploited CVE-2022-40684, an authentication bypass vulnerability affecting FortiOS, FortiProxy, and
    FortiSwitchManager. The group uses Cobalt Strike for post-exploitation and employs MITRE technique T1486
    for data encryption. Akira primarily targets the healthcare and education sectors.
    """,

    # 2. Lazarus Group / HIDDEN COBRA (CISA AA21-048A)
    """
    HIDDEN COBRA, also known as Lazarus Group, is a North Korean state-sponsored cyber group. The group uses
    BLINDINGCAN, a remote access trojan, to target financial institutions and cryptocurrency exchanges.
    Lazarus Group exploited CVE-2021-44228 (Log4Shell) in Apache Log4j to gain initial access. The group
    employs T1055 (Process Injection) and uses Mimikatz for credential theft.
    CVE-2021-44228 has weakness CWE-917 (Improper Neutralization of Special Elements).
    """,

    # 3. BlackTech (CISA AA23-270A)
    """
    BlackTech is a Chinese state-sponsored threat actor targeting organizations in Taiwan, Japan, and the
    United States, particularly in the defense and telecommunications sectors. BlackTech uses custom malware
    families including PLEAD and TSCookie. The group modifies router firmware to establish persistence and
    uses T1190 (Exploit Public-Facing Application) for initial access. BlackTech is attributed to China's
    Ministry of State Security. PLEAD employs T1059.003 (Windows Command Shell) for execution.
    """,

    # 4. REvil ransomware (CISA AA21-131A)
    """
    REvil (also known as Sodinokibi) is a ransomware-as-a-service group attributed to Russia. The group
    exploited CVE-2021-30116, a zero-day vulnerability in Kaseya VSA software, to compromise managed service
    providers. CVE-2021-30116 has weakness CWE-22 (Path Traversal). REvil uses Cobalt Strike for lateral
    movement, Mimikatz for credential harvesting, and BloodHound for Active Directory reconnaissance.
    The group employs T1486 for data encryption and T1027 for obfuscation, primarily targeting manufacturing
    and legal sectors.
    """,

    # 5. Volt Typhoon (CISA AA23-144A)
    """
    Volt Typhoon is a People's Republic of China state-sponsored cyber actor that targets critical
    infrastructure organizations in the United States, including communications, energy, and transportation
    sectors. Volt Typhoon exploited CVE-2023-27997, a heap-based buffer overflow in Fortinet FortiOS.
    CVE-2023-27997 has weakness CWE-122. The group uses living-off-the-land techniques including T1190
    (Exploit Public-Facing Application) and T1078 (Valid Accounts), and T1003.001 for OS credential dumping.
    """,
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def call_llm(client: OpenAI, report_text: str, model: str = "gpt-4o") -> str:
    relations_str = json.dumps(sorted(RELATION_WHITELIST))
    prompt = SYSTEM_PROMPT.format(relations=relations_str)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": f"{prompt}\n\nREPORT:\n{report_text}\n\nTRIPLETS (JSON array):"}],
        temperature=0,
        max_tokens=2000,
    )
    return response.choices[0].message.content


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def openai_client():
    settings = get_settings()
    return OpenAI(api_key=settings.openai_api_key)


@pytest.fixture(scope="module")
def all_results(openai_client):
    """Call GPT-4o for each advisory and collect accepted/rejected counts."""
    results = []
    for i, text in enumerate(ADVISORY_TEXTS, 1):
        raw_text = call_llm(openai_client, text)
        raw = parse_llm_response(raw_text)
        accepted, rejected = validate_triplets(raw)
        results.append({
            "batch": i,
            "raw_text": raw_text,
            "total": len(raw),
            "accepted": len(accepted),
            "rejected": len(rejected),
            "rejected_items": rejected,
            "rate": len(rejected) / len(raw) if raw else 0.0,
        })
    return results


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestLLMRejectionRate:

    def test_llm_returns_non_empty_output(self, all_results):
        for r in all_results:
            assert r["total"] > 0, f"Batch {r['batch']}: GPT-4o returned no triplets"

    @pytest.mark.parametrize("batch_idx", list(range(len(ADVISORY_TEXTS))))
    def test_per_batch_rejection_rate(self, all_results, batch_idx):
        r = all_results[batch_idx]
        assert r["rate"] < REJECTION_THRESHOLD, (
            f"Batch {r['batch']}: rejection rate {r['rate']:.0%} >= {REJECTION_THRESHOLD:.0%} "
            f"({r['rejected']} rejected / {r['total']} total)\n"
            f"Rejected: {r['rejected_items']}"
        )

    def test_overall_rejection_rate_below_threshold(self, all_results):
        total_accepted = sum(r["accepted"] for r in all_results)
        total_rejected = sum(r["rejected"] for r in all_results)
        total = total_accepted + total_rejected
        overall_rate = total_rejected / total if total > 0 else 0.0

        print(f"\n{'='*60}")
        print(f"LLM Output Rejection Rate Report (real GPT-4o calls)")
        print(f"{'='*60}")
        print(f"  {'Batch':<8} {'Accepted':>8} {'Rejected':>8} {'Rate':>8}")
        print(f"  {'-'*36}")
        for r in all_results:
            status = "✓" if r["rate"] < REJECTION_THRESHOLD else "✗"
            print(f"  {status} #{r['batch']:<6} {r['accepted']:>8} {r['rejected']:>8} {r['rate']:>7.1%}")
            for rej in r["rejected_items"]:
                print(f"       ✗ {rej.get('subject')} --[{rej.get('relation')}]--> {rej.get('object')}  ({rej.get('reason')})")
        print(f"  {'-'*36}")
        print(f"  {'TOTAL':<8} {total_accepted:>8} {total_rejected:>8} {overall_rate:>7.1%}")
        print(f"{'='*60}")
        print(f"  Threshold : < {REJECTION_THRESHOLD:.0%}")
        print(f"  Result    : {'PASS' if overall_rate < REJECTION_THRESHOLD else 'FAIL'}")
        print(f"{'='*60}\n")

        assert overall_rate < REJECTION_THRESHOLD, (
            f"Overall rejection rate {overall_rate:.1%} >= threshold {REJECTION_THRESHOLD:.0%} "
            f"({total_rejected} rejected / {total} total)"
        )
