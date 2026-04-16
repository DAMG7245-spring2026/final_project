"""Map NVD API 2.0 vulnerability JSON to cve_records-shaped rows."""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$")


def _parse_date(s: str) -> date:
    return date.fromisoformat(s[:10])


def _parse_ts_ntz(s: str) -> datetime:
    """NVD ISO timestamp -> naive UTC for TIMESTAMP_NTZ."""
    t = s.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    dt = datetime.fromisoformat(t)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _severity_from_v2_score(score: float | None) -> str:
    if score is None:
        return ""
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    return "HIGH"


def _pick_primary_metric(metrics_list: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not metrics_list:
        return None
    for m in metrics_list:
        if m.get("type") == "Primary" and "nvd" in (m.get("source") or "").lower():
            return m
    for m in metrics_list:
        if m.get("type") == "Primary":
            return m
    return metrics_list[0]


def extract_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize CVSS v3.1, v4.0, v3.0, v2.0 into flat fields matching cve_records.
    Missing metrics return None / empty string where appropriate.
    """
    empty: dict[str, Any] = {
        "cvss_version": None,
        "cvss_score": None,
        "cvss_severity": None,
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
        "scope": None,
        "confidentiality_impact": None,
        "integrity_impact": None,
        "exploitability_score": None,
        "impact_score": None,
    }
    if not metrics:
        return empty

    m31 = _pick_primary_metric(metrics.get("cvssMetricV31") or [])
    if m31 and "cvssData" in m31:
        d = m31["cvssData"]
        sev = (d.get("baseSeverity") or "")[:10]
        return {
            "cvss_version": "3.1",
            "cvss_score": d.get("baseScore"),
            "cvss_severity": sev,
            "attack_vector": (d.get("attackVector") or "")[:20],
            "attack_complexity": (d.get("attackComplexity") or "")[:10],
            "privileges_required": (d.get("privilegesRequired") or "")[:10],
            "user_interaction": (d.get("userInteraction") or "")[:10],
            "scope": (d.get("scope") or "")[:10],
            "confidentiality_impact": (d.get("confidentialityImpact") or "")[:10],
            "integrity_impact": (d.get("integrityImpact") or "")[:10],
            "exploitability_score": m31.get("exploitabilityScore"),
            "impact_score": m31.get("impactScore"),
        }

    m40 = _pick_primary_metric(metrics.get("cvssMetricV40") or [])
    if m40 and "cvssData" in m40:
        d = m40["cvssData"]
        sev = (d.get("baseSeverity") or "")[:10]
        return {
            "cvss_version": "4.0",
            "cvss_score": d.get("baseScore"),
            "cvss_severity": sev,
            "attack_vector": (d.get("attackVector") or "")[:20],
            "attack_complexity": (d.get("attackComplexity") or "")[:10],
            "privileges_required": (d.get("privilegesRequired") or "")[:10],
            "user_interaction": (d.get("userInteraction") or "")[:10],
            "scope": (d.get("scope") or "")[:10],
            "confidentiality_impact": (d.get("confidentialityImpact") or "")[:10],
            "integrity_impact": (d.get("integrityImpact") or "")[:10],
            "exploitability_score": m40.get("exploitabilityScore"),
            "impact_score": m40.get("impactScore"),
        }

    m30 = _pick_primary_metric(metrics.get("cvssMetricV30") or [])
    if m30 and "cvssData" in m30:
        d = m30["cvssData"]
        sev = (d.get("baseSeverity") or "")[:10]
        return {
            "cvss_version": "3.0",
            "cvss_score": d.get("baseScore"),
            "cvss_severity": sev,
            "attack_vector": (d.get("attackVector") or "")[:20],
            "attack_complexity": (d.get("attackComplexity") or "")[:10],
            "privileges_required": (d.get("privilegesRequired") or "")[:10],
            "user_interaction": (d.get("userInteraction") or "")[:10],
            "scope": (d.get("scope") or "")[:10],
            "confidentiality_impact": (d.get("confidentialityImpact") or "")[:10],
            "integrity_impact": (d.get("integrityImpact") or "")[:10],
            "exploitability_score": m30.get("exploitabilityScore"),
            "impact_score": m30.get("impactScore"),
        }

    m2 = _pick_primary_metric(metrics.get("cvssMetricV2") or [])
    if m2 and "cvssData" in m2:
        d = m2["cvssData"]
        score = d.get("baseScore")
        sev = _severity_from_v2_score(float(score)) if score is not None else ""
        auth = d.get("authentication") or ""
        return {
            "cvss_version": "2.0",
            "cvss_score": float(score) if score is not None else None,
            "cvss_severity": sev[:10],
            "attack_vector": (d.get("accessVector") or "")[:20],
            "attack_complexity": (d.get("accessComplexity") or "")[:10],
            "privileges_required": (str(auth) or "")[:10],
            "user_interaction": "",
            "scope": "",
            "confidentiality_impact": (d.get("confidentialityImpact") or "")[:10],
            "integrity_impact": (d.get("integrityImpact") or "")[:10],
            "exploitability_score": m2.get("exploitabilityScore"),
            "impact_score": m2.get("impactScore"),
        }

    return empty


def _cwe_ids(cve: dict[str, Any]) -> list[str]:
    primary: list[str] = []
    secondary: list[str] = []
    for w in cve.get("weaknesses") or []:
        w_type = (w.get("type") or "").strip()
        if w_type not in {"Primary", "Secondary"}:
            continue
        for desc in w.get("description") or []:
            if desc.get("lang") != "en":
                continue
            val = (desc.get("value") or "").strip()
            if val.startswith("CWE-"):
                if w_type == "Primary":
                    primary.append(val[:20])
                else:
                    secondary.append(val[:20])

    # Never mix types: prefer Primary, fallback to Secondary.
    return primary or secondary


def _cpe_criteria(cve: dict[str, Any]) -> list[str]:
    cpe: list[str] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") and m.get("criteria"):
                    cpe.append(str(m["criteria"])[:500])
    return cpe


def _has_exploit_ref(cve: dict[str, Any]) -> bool:
    for ref in cve.get("references") or []:
        tags = ref.get("tags") or []
        if any(str(t) == "Exploit" for t in tags):
            return True
    return False


class CveSnowflakeRecord(BaseModel):
    """Validated row for cve_records (NVD-owned columns only for upsert)."""

    cve_id: str
    source_identifier: str | None = Field(default=None, max_length=100)
    published_date: date
    last_modified: datetime
    vuln_status: str = Field(default="", max_length=50)
    description_en: str = ""
    cvss_version: str | None = Field(default=None, max_length=5)
    cvss_score: float | None = None
    cvss_severity: str | None = Field(default=None, max_length=10)
    attack_vector: str | None = Field(default=None, max_length=20)
    attack_complexity: str | None = Field(default=None, max_length=10)
    privileges_required: str | None = Field(default=None, max_length=10)
    user_interaction: str | None = Field(default=None, max_length=10)
    scope: str | None = Field(default=None, max_length=10)
    confidentiality_impact: str | None = Field(default=None, max_length=10)
    integrity_impact: str | None = Field(default=None, max_length=10)
    exploitability_score: float | None = None
    impact_score: float | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    cpe_matches: list[str] = Field(default_factory=list)
    has_exploit_ref: bool = False
    raw_json: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cve_id")
    @classmethod
    def cve_id_format(cls, v: str) -> str:
        if not CVE_ID_RE.match(v):
            raise ValueError(f"Invalid CVE ID: {v}")
        return v

    @field_validator("cvss_score")
    @classmethod
    def cvss_score_range(cls, v: float | None) -> float | None:
        if v is not None and not 0.0 <= float(v) <= 10.0:
            raise ValueError(f"CVSS score out of range: {v}")
        return v


def transform_vulnerability(raw: dict[str, Any]) -> dict[str, Any]:
    """
    One element from NVD `vulnerabilities[]` -> dict for Snowflake upsert
    (includes `raw_json` as the full vulnerability object).
    """
    cve = raw["cve"]
    cve_id = cve["id"]
    metrics = cve.get("metrics") or {}
    cv = extract_cvss(metrics)

    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        None,
    )

    rec = CveSnowflakeRecord(
        cve_id=cve_id,
        source_identifier=(cve.get("sourceIdentifier") or None),
        published_date=_parse_date(cve["published"]),
        last_modified=_parse_ts_ntz(cve["lastModified"]),
        vuln_status=(cve.get("vulnStatus") or "")[:50],
        description_en=(desc or "")[:16000],
        cvss_version=cv["cvss_version"],
        cvss_score=cv["cvss_score"],
        cvss_severity=cv["cvss_severity"] or None,
        attack_vector=cv["attack_vector"] or None,
        attack_complexity=cv["attack_complexity"] or None,
        privileges_required=cv["privileges_required"] or None,
        user_interaction=cv["user_interaction"] or None,
        scope=cv["scope"] or None,
        confidentiality_impact=cv["confidentiality_impact"] or None,
        integrity_impact=cv["integrity_impact"] or None,
        exploitability_score=cv["exploitability_score"],
        impact_score=cv["impact_score"],
        cwe_ids=_cwe_ids(cve),
        cpe_matches=_cpe_criteria(cve),
        has_exploit_ref=_has_exploit_ref(cve),
        raw_json=raw,
    )
    return rec.model_dump()
