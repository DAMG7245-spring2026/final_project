"""Unit tests for NVD transform (no HTTP / Snowflake)."""

import pytest

from ingestion.nvd.transform import extract_cvss, transform_vulnerability

MINIMAL_VULN = {
    "cve": {
        "id": "CVE-2024-21413",
        "sourceIdentifier": "nvd@nist.gov",
        "published": "2024-02-13T00:00:00.000",
        "lastModified": "2024-03-15T18:07:44.223",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "en", "value": "Microsoft Outlook remote code execution."}
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9,
                }
            ]
        },
        "weaknesses": [
            {
                "type": "Primary",
                "description": [
                    {"lang": "en", "value": "CWE-787"},
                ],
            }
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
        "references": [
            {
                "url": "https://example.com/exploit",
                "tags": ["Exploit"],
            }
        ],
    }
}


def test_extract_cvss_v31_primary():
    m = MINIMAL_VULN["cve"]["metrics"]
    cv = extract_cvss(m)
    assert cv["cvss_version"] == "3.1"
    assert cv["cvss_score"] == 9.8
    assert cv["cvss_severity"] == "CRITICAL"
    assert cv["attack_vector"] == "NETWORK"
    assert cv["confidentiality_impact"] == "HIGH"
    assert cv["integrity_impact"] == "HIGH"
    assert cv["exploitability_score"] == 3.9
    assert cv["impact_score"] == 5.9


def test_transform_vulnerability_maps_row():
    row = transform_vulnerability(MINIMAL_VULN)
    assert row["cve_id"] == "CVE-2024-21413"
    assert row["source_identifier"] == "nvd@nist.gov"
    assert row["vuln_status"] == "Analyzed"
    assert "Outlook" in row["description_en"]
    assert row["cvss_score"] == 9.8
    assert row["cwe_ids"] == ["CWE-787"]
    assert row["has_exploit_ref"] is True
    assert any("microsoft:outlook" in c for c in row["cpe_matches"])
    assert row["raw_json"]["cve"]["id"] == "CVE-2024-21413"


def test_extract_cvss_v40_fallback_when_no_v31():
    vuln = {
        "cve": {
            **{k: v for k, v in MINIMAL_VULN["cve"].items() if k != "metrics"},
            "metrics": {
                "cvssMetricV40": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "4.0",
                            "baseScore": 8.7,
                            "baseSeverity": "HIGH",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "PASSIVE",
                            "scope": "CHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                        },
                        "exploitabilityScore": 2.4,
                        "impactScore": 6.3,
                    }
                ]
            },
        }
    }
    row = transform_vulnerability(vuln)
    assert row["cvss_version"] == "4.0"
    assert row["cvss_score"] == 8.7
    assert row["cvss_severity"] == "HIGH"
    assert row["user_interaction"] == "PASSIVE"


def test_transform_falls_back_to_secondary_cwe_when_primary_missing():
    vuln = {
        "cve": {
            **{k: v for k, v in MINIMAL_VULN["cve"].items() if k != "weaknesses"},
            "weaknesses": [
                {
                    "type": "Secondary",
                    "description": [{"lang": "en", "value": "CWE-79"}],
                }
            ],
        }
    }
    row = transform_vulnerability(vuln)
    assert row["cwe_ids"] == ["CWE-79"]


def test_transform_prefers_primary_cwe_and_does_not_mix_secondary():
    vuln = {
        "cve": {
            **{k: v for k, v in MINIMAL_VULN["cve"].items() if k != "weaknesses"},
            "weaknesses": [
                {
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-120"}],
                },
                {
                    "type": "Secondary",
                    "description": [{"lang": "en", "value": "CWE-79"}],
                },
            ],
        }
    }
    row = transform_vulnerability(vuln)
    assert row["cwe_ids"] == ["CWE-120"]


def test_invalid_cve_id_raises():
    bad = {
        "cve": {
            "id": "not-a-cve",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "x"}],
        }
    }
    with pytest.raises(ValueError, match="Invalid CVE"):
        transform_vulnerability(bad)
