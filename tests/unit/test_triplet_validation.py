"""Unit tests for LLM triplet output validation.

Covers:
- Pydantic schema validation: every field is required and typed correctly
- Relation whitelist enforcement: only the 7 allowed relation types pass
- Vague/empty entity rejection
- parse_llm_response: handles plain JSON and markdown code fences
- validate_triplets: accepted vs rejected separation
- dedup: case-insensitive deduplication
"""

import json
import pytest
from pydantic import ValidationError

from scripts.extract_triplets import (
    RELATION_WHITELIST,
    VAGUE_TERMS,
    Triplet,
    dedup,
    parse_llm_response,
    validate_triplets,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

VALID_TRIPLETS_RAW = [
    {"subject": "APT29", "relation": "uses", "object": "Cobalt Strike"},
    {"subject": "Lazarus Group", "relation": "targets", "object": "financial sector"},
    {"subject": "DarkSide", "relation": "exploits", "object": "CVE-2021-34527"},
    {"subject": "APT41", "relation": "attributed_to", "object": "China"},
    {"subject": "Log4Shell", "relation": "affects", "object": "Apache Log4j"},
    {"subject": "CVE-2022-30190", "relation": "has_weakness", "object": "CWE-94"},
    {"subject": "Microsoft Defender", "relation": "mitigates", "object": "T1059"},
]

REJECTED_RELATIONS = [
    "drops",
    "delivers",
    "indicates",
    "associated_with",
    "related_to",
    "installs",
    "communicates_with",
    "downloads",
    "",
    "USES",           # case-sensitive: only lowercase allowed
    "Uses",
]


# ── Pydantic schema: valid triplets ───────────────────────────────────────────

class TestTripletSchemaValid:
    @pytest.mark.parametrize("raw", VALID_TRIPLETS_RAW)
    def test_each_whitelisted_relation_is_accepted(self, raw):
        t = Triplet(**raw)
        assert t.relation == raw["relation"]
        assert t.subject == raw["subject"].strip()
        assert t.object == raw["object"].strip()

    def test_all_seven_relations_covered(self):
        relations_tested = {r["relation"] for r in VALID_TRIPLETS_RAW}
        assert relations_tested == RELATION_WHITELIST

    def test_whitelist_has_exactly_seven_relations(self):
        assert len(RELATION_WHITELIST) == 7

    def test_subject_and_object_are_stripped(self):
        t = Triplet(subject="  APT29  ", relation="uses", object="  Cobalt Strike  ")
        assert t.subject == "APT29"
        assert t.object == "Cobalt Strike"


# ── Pydantic schema: invalid relation types ───────────────────────────────────

class TestRelationWhitelist:
    @pytest.mark.parametrize("bad_relation", REJECTED_RELATIONS)
    def test_non_whitelisted_relation_raises_validation_error(self, bad_relation):
        with pytest.raises((ValidationError, ValueError)):
            Triplet(subject="APT29", relation=bad_relation, object="Windows")

    def test_error_message_mentions_whitelist(self):
        with pytest.raises(ValidationError) as exc_info:
            Triplet(subject="APT29", relation="drops", object="Windows")
        assert "whitelist" in str(exc_info.value).lower()

    def test_valid_relation_does_not_raise(self):
        t = Triplet(subject="APT29", relation="uses", object="Cobalt Strike")
        assert t.relation == "uses"

    @pytest.mark.parametrize("relation", RELATION_WHITELIST)
    def test_every_whitelisted_relation_passes(self, relation):
        t = Triplet(subject="GroupX", relation=relation, object="TargetY")
        assert t.relation == relation


# ── Pydantic schema: vague / empty entities ───────────────────────────────────

class TestEntityValidation:
    @pytest.mark.parametrize("vague", list(VAGUE_TERMS)[:6])
    def test_vague_subject_is_rejected(self, vague):
        with pytest.raises((ValidationError, ValueError)):
            Triplet(subject=vague, relation="uses", object="Windows")

    @pytest.mark.parametrize("vague", list(VAGUE_TERMS)[:6])
    def test_vague_object_is_rejected(self, vague):
        with pytest.raises((ValidationError, ValueError)):
            Triplet(subject="APT29", relation="uses", object=vague)

    def test_empty_subject_is_rejected(self):
        with pytest.raises((ValidationError, ValueError)):
            Triplet(subject="   ", relation="uses", object="Windows")

    def test_empty_object_is_rejected(self):
        with pytest.raises((ValidationError, ValueError)):
            Triplet(subject="APT29", relation="uses", object="")

    def test_missing_subject_field_raises(self):
        with pytest.raises((ValidationError, TypeError)):
            Triplet(relation="uses", object="Windows")

    def test_missing_relation_field_raises(self):
        with pytest.raises((ValidationError, TypeError)):
            Triplet(subject="APT29", object="Windows")

    def test_missing_object_field_raises(self):
        with pytest.raises((ValidationError, TypeError)):
            Triplet(subject="APT29", relation="uses")


# ── parse_llm_response ────────────────────────────────────────────────────────

class TestParseLlmResponse:
    def test_parses_plain_json_array(self):
        raw = json.dumps([{"subject": "APT29", "relation": "uses", "object": "Cobalt Strike"}])
        result = parse_llm_response(raw)
        assert len(result) == 1
        assert result[0]["relation"] == "uses"

    def test_strips_json_markdown_fence(self):
        raw = '```json\n[{"subject": "APT29", "relation": "uses", "object": "Cobalt Strike"}]\n```'
        result = parse_llm_response(raw)
        assert len(result) == 1

    def test_strips_plain_markdown_fence(self):
        raw = '```\n[{"subject": "APT29", "relation": "uses", "object": "Cobalt Strike"}]\n```'
        result = parse_llm_response(raw)
        assert len(result) == 1

    def test_parses_empty_array(self):
        assert parse_llm_response("[]") == []

    def test_invalid_json_raises(self):
        with pytest.raises((json.JSONDecodeError, Exception)):
            parse_llm_response("not valid json")

    def test_preserves_multiple_triplets(self):
        data = [
            {"subject": "APT29", "relation": "uses", "object": "Cobalt Strike"},
            {"subject": "Lazarus Group", "relation": "targets", "object": "financial sector"},
        ]
        result = parse_llm_response(json.dumps(data))
        assert len(result) == 2


# ── validate_triplets ─────────────────────────────────────────────────────────

class TestValidateTriplets:
    def test_all_valid_returns_all_accepted(self):
        accepted, rejected = validate_triplets(VALID_TRIPLETS_RAW)
        assert len(accepted) == len(VALID_TRIPLETS_RAW)
        assert rejected == []

    def test_all_invalid_returns_all_rejected(self):
        bad = [
            {"subject": "APT29", "relation": "drops", "object": "Windows"},
            {"subject": "APT29", "relation": "delivers", "object": "Windows"},
            {"subject": "APT29", "relation": "indicates", "object": "Windows"},
        ]
        accepted, rejected = validate_triplets(bad)
        assert accepted == []
        assert len(rejected) == 3

    def test_mixed_batch_is_correctly_split(self):
        raw = [
            {"subject": "APT29", "relation": "uses", "object": "Cobalt Strike"},   # valid
            {"subject": "APT29", "relation": "drops", "object": "Windows"},         # bad relation
            {"subject": "Lazarus Group", "relation": "targets", "object": "banks"}, # valid
            {"subject": "the attacker", "relation": "uses", "object": "Windows"},   # vague entity
        ]
        accepted, rejected = validate_triplets(raw)
        assert len(accepted) == 2
        assert len(rejected) == 2

    def test_rejected_entries_include_reason_field(self):
        bad = [{"subject": "APT29", "relation": "associated_with", "object": "Russia"}]
        _, rejected = validate_triplets(bad)
        assert "reason" in rejected[0]
        assert "whitelist" in rejected[0]["reason"].lower()

    def test_accepted_entries_are_triplet_instances(self):
        accepted, _ = validate_triplets(VALID_TRIPLETS_RAW[:1])
        assert isinstance(accepted[0], Triplet)

    def test_empty_input_returns_empty_lists(self):
        accepted, rejected = validate_triplets([])
        assert accepted == []
        assert rejected == []

    def test_relation_outside_whitelist_goes_to_rejected(self):
        bad_relations = ["drops", "delivers", "indicates", "associated_with", "installs"]
        raw = [{"subject": "APT29", "relation": r, "object": "Windows"} for r in bad_relations]
        accepted, rejected = validate_triplets(raw)
        assert accepted == []
        assert len(rejected) == len(bad_relations)

    def test_original_fields_preserved_in_rejected(self):
        raw = [{"subject": "APT29", "relation": "drops", "object": "Windows"}]
        _, rejected = validate_triplets(raw)
        assert rejected[0]["subject"] == "APT29"
        assert rejected[0]["relation"] == "drops"
        assert rejected[0]["object"] == "Windows"


# ── dedup ─────────────────────────────────────────────────────────────────────

class TestDedup:
    def _make(self, subject, relation, obj):
        return Triplet(subject=subject, relation=relation, object=obj)

    def test_exact_duplicate_is_removed(self):
        triplets = [
            self._make("APT29", "uses", "Cobalt Strike"),
            self._make("APT29", "uses", "Cobalt Strike"),
        ]
        result = dedup(triplets)
        assert len(result) == 1

    def test_case_insensitive_subject_dedup(self):
        triplets = [
            self._make("APT29", "uses", "Cobalt Strike"),
            self._make("apt29", "uses", "Cobalt Strike"),
        ]
        result = dedup(triplets)
        assert len(result) == 1

    def test_case_insensitive_object_dedup(self):
        triplets = [
            self._make("APT29", "uses", "Cobalt Strike"),
            self._make("APT29", "uses", "cobalt strike"),
        ]
        result = dedup(triplets)
        assert len(result) == 1

    def test_different_relation_not_deduped(self):
        triplets = [
            self._make("APT29", "uses", "Cobalt Strike"),
            self._make("APT29", "targets", "Cobalt Strike"),
        ]
        result = dedup(triplets)
        assert len(result) == 2

    def test_different_subject_not_deduped(self):
        triplets = [
            self._make("APT29", "uses", "Cobalt Strike"),
            self._make("Lazarus Group", "uses", "Cobalt Strike"),
        ]
        result = dedup(triplets)
        assert len(result) == 2

    def test_different_object_not_deduped(self):
        triplets = [
            self._make("APT29", "uses", "Cobalt Strike"),
            self._make("APT29", "uses", "Mimikatz"),
        ]
        result = dedup(triplets)
        assert len(result) == 2

    def test_empty_list_returns_empty(self):
        assert dedup([]) == []

    def test_first_occurrence_is_kept(self):
        triplets = [
            self._make("APT29", "uses", "Cobalt Strike"),
            self._make("APT29", "uses", "Cobalt Strike"),
        ]
        result = dedup(triplets)
        assert result[0].subject == "APT29"


# ── End-to-end: simulated LLM response → validate ────────────────────────────

class TestEndToEndLlmResponseValidation:
    """Simulate the full path: raw LLM string → parse → validate."""

    def _run(self, llm_output: str):
        raw_list = parse_llm_response(llm_output)
        return validate_triplets(raw_list)

    def test_clean_llm_response_all_accepted(self):
        payload = [
            {"subject": "APT29", "relation": "uses", "object": "Cobalt Strike"},
            {"subject": "Lazarus Group", "relation": "exploits", "object": "CVE-2021-44228"},
        ]
        accepted, rejected = self._run(json.dumps(payload))
        assert len(accepted) == 2
        assert rejected == []

    def test_llm_response_with_bad_relations_all_rejected(self):
        payload = [
            {"subject": "APT29", "relation": "drops", "object": "Cobalt Strike"},
            {"subject": "APT29", "relation": "delivers", "object": "payload.exe"},
            {"subject": "APT29", "relation": "associated_with", "object": "Russia"},
        ]
        accepted, rejected = self._run(json.dumps(payload))
        assert accepted == []
        assert len(rejected) == 3

    def test_llm_response_in_markdown_fence_is_parsed_and_validated(self):
        payload = [{"subject": "DarkSide", "relation": "affects", "object": "Colonial Pipeline"}]
        raw = f"```json\n{json.dumps(payload)}\n```"
        accepted, rejected = self._run(raw)
        assert len(accepted) == 1
        assert rejected == []

    def test_llm_response_with_vague_entities_rejected(self):
        payload = [
            {"subject": "the attacker", "relation": "uses", "object": "Cobalt Strike"},
            {"subject": "APT29", "relation": "uses", "object": "malware"},
        ]
        accepted, rejected = self._run(json.dumps(payload))
        assert accepted == []
        assert len(rejected) == 2

    def test_llm_empty_response_produces_nothing(self):
        accepted, rejected = self._run("[]")
        assert accepted == []
        assert rejected == []

    def test_mixed_llm_response_split_correctly(self):
        payload = [
            {"subject": "APT29", "relation": "uses", "object": "Cobalt Strike"},      # valid
            {"subject": "APT29", "relation": "indicates", "object": "nation-state"},  # bad relation
            {"subject": "threat actors", "relation": "targets", "object": "banks"},   # vague subject
            {"subject": "Log4Shell", "relation": "affects", "object": "Apache"},      # valid
        ]
        accepted, rejected = self._run(json.dumps(payload))
        assert len(accepted) == 2
        assert len(rejected) == 2
        accepted_relations = {t.relation for t in accepted}
        assert accepted_relations <= RELATION_WHITELIST
