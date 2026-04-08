"""Tests for purpleforge.analysis.findings_schema."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from purpleforge.analysis.findings_schema import (
    Finding,
    compute_finding_id,
    dump_findings,
    load_findings,
    summarize,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        source="ghidra_binary",
        category="suspicious_import",
        title="Test finding",
        description="A test finding for unit tests",
        severity="medium",
        confidence="medium",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Valid construction
# ---------------------------------------------------------------------------

class TestFindingConstruction:
    def test_minimal_valid_finding(self):
        f = _make_finding()
        assert f.source == "ghidra_binary"
        assert f.category == "suspicious_import"
        assert f.severity == "medium"
        assert f.confidence == "medium"

    def test_finding_id_auto_populated(self):
        f = _make_finding()
        assert f.finding_id
        assert len(f.finding_id) == 16
        assert all(c in "0123456789abcdef" for c in f.finding_id)

    def test_finding_id_not_overwritten_when_provided(self):
        custom_id = "aabbccddeeff0011"
        f = _make_finding(finding_id=custom_id)
        assert f.finding_id == custom_id

    def test_defaults_populated(self):
        f = _make_finding()
        assert f.evidence == {}
        assert f.location is None
        assert f.file_path is None
        assert isinstance(f.created_at, datetime)

    def test_optional_fields(self):
        f = _make_finding(
            location="kernel32.dll!VirtualAlloc",
            file_path="/tmp/sample.exe",
            evidence={"raw": "VirtualAlloc"},
        )
        assert f.location == "kernel32.dll!VirtualAlloc"
        assert f.file_path == "/tmp/sample.exe"
        assert f.evidence == {"raw": "VirtualAlloc"}


# ---------------------------------------------------------------------------
# Deterministic finding_id
# ---------------------------------------------------------------------------

class TestComputeFindingId:
    def test_same_inputs_same_id(self):
        id1 = compute_finding_id("ghidra_binary", "suspicious_import", "VirtualAlloc", "suspicious import")
        id2 = compute_finding_id("ghidra_binary", "suspicious_import", "VirtualAlloc", "suspicious import")
        assert id1 == id2

    def test_different_inputs_different_id(self):
        id1 = compute_finding_id("ghidra_binary", "suspicious_import", "VirtualAlloc", "suspicious import")
        id2 = compute_finding_id("ghidra_binary", "suspicious_section", ".rwx", "rwx section found")
        assert id1 != id2

    def test_id_length_is_16(self):
        fid = compute_finding_id("src", "cat", "loc", "desc")
        assert len(fid) == 16

    def test_normalisation_case_insensitive(self):
        id1 = compute_finding_id("GHIDRA_BINARY", "Suspicious_Import", "VirtualAlloc", "A desc")
        id2 = compute_finding_id("ghidra_binary", "suspicious_import", "virtualalloc", "a desc")
        assert id1 == id2

    def test_none_location_treated_as_empty(self):
        id1 = compute_finding_id("src", "cat", None, "desc")
        id2 = compute_finding_id("src", "cat", "", "desc")
        assert id1 == id2

    def test_findings_with_same_fields_have_same_id(self):
        f1 = _make_finding(description="unique desc xyz", location="addr_0x1234")
        f2 = _make_finding(description="unique desc xyz", location="addr_0x1234")
        assert f1.finding_id == f2.finding_id

    def test_findings_with_different_descriptions_differ(self):
        f1 = _make_finding(description="desc A")
        f2 = _make_finding(description="desc B")
        assert f1.finding_id != f2.finding_id


# ---------------------------------------------------------------------------
# summarize()
# ---------------------------------------------------------------------------

class TestSummarize:
    def test_empty_list(self):
        result = summarize([])
        assert result["total"] == 0
        assert result["by_severity"] == {"low": 0, "medium": 0, "high": 0}
        assert result["by_category"] == {}

    def test_counts_by_severity(self):
        findings = [
            _make_finding(severity="high"),
            _make_finding(severity="high", description="another high"),
            _make_finding(severity="medium", description="medium one"),
            _make_finding(severity="low", description="low one"),
        ]
        result = summarize(findings)
        assert result["total"] == 4
        assert result["by_severity"]["high"] == 2
        assert result["by_severity"]["medium"] == 1
        assert result["by_severity"]["low"] == 1

    def test_counts_by_category(self):
        findings = [
            _make_finding(category="suspicious_import", description="d1"),
            _make_finding(category="suspicious_import", description="d2"),
            _make_finding(category="suspicious_string", description="d3"),
        ]
        result = summarize(findings)
        assert result["by_category"]["suspicious_import"] == 2
        assert result["by_category"]["suspicious_string"] == 1

    def test_total_matches_list_length(self):
        findings = [_make_finding(description=f"desc {i}") for i in range(7)]
        result = summarize(findings)
        assert result["total"] == 7


# ---------------------------------------------------------------------------
# dump_findings / load_findings roundtrip
# ---------------------------------------------------------------------------

class TestDumpLoadRoundtrip:
    def test_roundtrip_single_finding(self, tmp_path):
        f = _make_finding(location="VirtualAlloc", file_path="/tmp/test.exe")
        out = tmp_path / "findings.json"
        dump_findings([f], out)
        assert out.exists()
        loaded = load_findings(out)
        assert len(loaded) == 1
        assert loaded[0].finding_id == f.finding_id
        assert loaded[0].source == f.source
        assert loaded[0].category == f.category
        assert loaded[0].location == f.location
        assert loaded[0].file_path == f.file_path

    def test_roundtrip_multiple_findings(self, tmp_path):
        findings = [_make_finding(description=f"desc {i}") for i in range(5)]
        out = tmp_path / "multi.json"
        dump_findings(findings, out)
        loaded = load_findings(out)
        assert len(loaded) == 5
        original_ids = {f.finding_id for f in findings}
        loaded_ids = {f.finding_id for f in loaded}
        assert original_ids == loaded_ids

    def test_output_is_valid_json_with_indent(self, tmp_path):
        f = _make_finding()
        out = tmp_path / "out.json"
        dump_findings([f], out)
        raw = out.read_text(encoding="utf-8")
        parsed = json.loads(raw)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_datetimes_serialized_as_strings(self, tmp_path):
        f = _make_finding()
        out = tmp_path / "out.json"
        dump_findings([f], out)
        parsed = json.loads(out.read_text(encoding="utf-8"))
        # created_at must be a string in the JSON
        assert isinstance(parsed[0]["created_at"], str)

    def test_empty_list_roundtrip(self, tmp_path):
        out = tmp_path / "empty.json"
        dump_findings([], out)
        loaded = load_findings(out)
        assert loaded == []

    def test_creates_parent_dirs(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c" / "findings.json"
        f = _make_finding()
        dump_findings([f], nested)
        assert nested.exists()


# ---------------------------------------------------------------------------
# Invalid severity raises ValidationError
# ---------------------------------------------------------------------------

class TestValidation:
    def test_invalid_severity_raises(self):
        with pytest.raises(ValidationError):
            _make_finding(severity="critical")  # type: ignore[arg-type]

    def test_invalid_confidence_raises(self):
        with pytest.raises(ValidationError):
            _make_finding(confidence="very_high")  # type: ignore[arg-type]

    def test_missing_required_fields_raises(self):
        with pytest.raises(ValidationError):
            Finding(severity="high", confidence="high")  # type: ignore[call-arg]
