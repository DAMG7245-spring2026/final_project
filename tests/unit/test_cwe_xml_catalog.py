"""Tests for MITRE cwec XML → JSON catalog conversion."""

import json
from pathlib import Path

import xml.etree.ElementTree as ET

import pytest

from ingestion.cwe.xml_catalog import (
    convert_cwec_xml_file_to_catalog_json,
    weaknesses_dicts_from_xml_tree,
)


MINIMAL_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Draft">
      <Description>Hello &amp; world.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


def test_weaknesses_dicts_from_xml_tree_parses_weakness():
    root = ET.fromstring(MINIMAL_XML)
    rows = weaknesses_dicts_from_xml_tree(root)
    assert len(rows) == 1
    assert rows[0]["CWE_ID"] == 79
    assert rows[0]["Name"] == "Cross-site Scripting"
    assert rows[0]["Abstraction"] == "Base"
    assert rows[0]["Status"] == "Draft"
    assert rows[0]["Description"] == "Hello & world."


def test_convert_cwec_xml_file_to_catalog_json_writes_document(tmp_path: Path):
    xml_path = tmp_path / "cwec.xml"
    xml_path.write_bytes(MINIMAL_XML)
    json_path = tmp_path / "out.json"
    doc = convert_cwec_xml_file_to_catalog_json(xml_path, json_path)
    assert doc["_format"] == "converted_from_mitre_cwec_xml"
    assert len(doc["weaknesses"]) == 1
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["weaknesses"][0]["CWE_ID"] == 79


def test_weaknesses_missing_weaknesses_raises():
    root = ET.fromstring(
        b'<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"></Weakness_Catalog>'
    )
    with pytest.raises(ValueError, match="missing"):
        weaknesses_dicts_from_xml_tree(root)
