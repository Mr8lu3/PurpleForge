"""Tests for purpleforge.analysis.binary_analyzer."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from purpleforge.analysis.binary_analyzer import BinaryAnalyzer
from purpleforge.analysis.findings_schema import Finding, load_findings
from purpleforge.utils.exceptions import AnalysisError


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_RESULTS = {
    "metadata": {"name": "sample.exe", "language": "x86:LE:32:default", "compiler": "unknown",
                 "format": "Portable Executable (PE)", "image_base": "0x400000",
                 "min_address": "0x401000", "max_address": "0x40f000"},
    "sections": [
        {"name": ".text", "start": "0x401000", "end": "0x408fff", "size": 32768,
         "permissions": {"read": True, "write": False, "execute": True}},
        {"name": ".rwx", "start": "0x409000", "end": "0x40afff", "size": 8192,
         "permissions": {"read": True, "write": True, "execute": True}},
    ],
    "functions": [],
    "imports": [
        {"name": "VirtualAlloc", "address": "0x0", "library": "KERNEL32.DLL"},
        {"name": "GetProcAddress", "address": "0x0", "library": "KERNEL32.DLL"},
    ],
    "exports": [],
    "strings": [
        {"address": "0x40b000", "value": "http://example.com/payload", "type": "TerminatedCString"},
        {"address": "0x40b100", "value": "cmd.exe /c whoami", "type": "TerminatedCString"},
    ],
}

SAMPLE_INDICATORS = [
    {
        "type": "suspicious_import",
        "value": "VirtualAlloc",
        "description": "Potentially suspicious API import: VirtualAlloc",
        "severity": "medium",
    },
    {
        "type": "suspicious_import",
        "value": "GetProcAddress",
        "description": "Potentially suspicious API import: GetProcAddress",
        "severity": "medium",
    },
    {
        "type": "suspicious_string",
        "value": "http://example.com/payload",
        "description": "URL string found",
        "severity": "low",
    },
    {
        "type": "suspicious_string",
        "value": "cmd.exe /c whoami",
        "description": "Command shell reference",
        "severity": "low",
    },
    {
        "type": "suspicious_section",
        "value": ".rwx",
        "description": "Section .rwx has RWX permissions",
        "severity": "high",
    },
]


def _make_fake_analyzer(results=SAMPLE_RESULTS, indicators=SAMPLE_INDICATORS):
    """Build a MagicMock GhidraAnalyzer with canned responses."""
    fake = MagicMock()
    fake.analyze.return_value = results
    fake.get_suspicious_indicators.return_value = indicators
    fake.is_available.return_value = True
    return fake


# ---------------------------------------------------------------------------
# Ghidra unavailable → AnalysisError
# ---------------------------------------------------------------------------

class TestGhidraUnavailable:
    def test_raises_analysis_error_when_no_analyzer(self, tmp_path):
        with patch("purpleforge.analysis.binary_analyzer.get_ghidra_analyzer", return_value=None):
            analyzer = BinaryAnalyzer()
        fake_bin = tmp_path / "sample.exe"
        fake_bin.write_bytes(b"\x4d\x5a")
        with pytest.raises(AnalysisError) as exc_info:
            analyzer.analyze(fake_bin, tmp_path / "out")
        assert "Ghidra not available" in exc_info.value.message

    def test_hint_mentions_ghidra_home(self, tmp_path):
        with patch("purpleforge.analysis.binary_analyzer.get_ghidra_analyzer", return_value=None):
            analyzer = BinaryAnalyzer()
        fake_bin = tmp_path / "sample.exe"
        fake_bin.write_bytes(b"\x4d\x5a")
        with pytest.raises(AnalysisError) as exc_info:
            analyzer.analyze(fake_bin, tmp_path / "out")
        assert exc_info.value.hint is not None
        assert "GHIDRA_HOME" in exc_info.value.hint

    def test_raises_analysis_error_when_binary_missing(self, tmp_path):
        fake_analyzer = _make_fake_analyzer()
        analyzer = BinaryAnalyzer(ghidra_analyzer=fake_analyzer)
        missing = tmp_path / "does_not_exist.exe"
        with pytest.raises(AnalysisError) as exc_info:
            analyzer.analyze(missing, tmp_path / "out")
        assert "Binary not found" in exc_info.value.message


# ---------------------------------------------------------------------------
# Fake analyzer returns canned results → expected Findings
# ---------------------------------------------------------------------------

class TestAnalyzeWithFakeGhidra:
    def test_returns_correct_number_of_findings(self, tmp_path):
        fake_analyzer = _make_fake_analyzer()
        analyzer = BinaryAnalyzer(ghidra_analyzer=fake_analyzer)

        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x4d\x5a\x90\x00")
        out_dir = tmp_path / "out"

        findings = analyzer.analyze(binary, out_dir)
        assert len(findings) == len(SAMPLE_INDICATORS)

    def test_ghidra_analyze_called_with_output_dir(self, tmp_path):
        fake_analyzer = _make_fake_analyzer()
        analyzer = BinaryAnalyzer(ghidra_analyzer=fake_analyzer)

        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x4d\x5a\x90\x00")
        out_dir = tmp_path / "out"

        analyzer.analyze(binary, out_dir)

        fake_analyzer.analyze.assert_called_once()
        call_kwargs = fake_analyzer.analyze.call_args
        # output_dir must be passed
        assert call_kwargs.kwargs.get("output_dir") == out_dir or (
            len(call_kwargs.args) > 1 and call_kwargs.args[1] == out_dir
        )

    def test_binary_findings_json_written(self, tmp_path):
        fake_analyzer = _make_fake_analyzer()
        analyzer = BinaryAnalyzer(ghidra_analyzer=fake_analyzer)

        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x4d\x5a\x90\x00")
        out_dir = tmp_path / "out"

        analyzer.analyze(binary, out_dir)

        findings_path = out_dir / "binary_findings.json"
        assert findings_path.exists()

        loaded = load_findings(findings_path)
        assert len(loaded) == len(SAMPLE_INDICATORS)

    def test_all_findings_are_Finding_instances(self, tmp_path):
        fake_analyzer = _make_fake_analyzer()
        analyzer = BinaryAnalyzer(ghidra_analyzer=fake_analyzer)

        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x4d\x5a\x90\x00")

        findings = analyzer.analyze(binary, tmp_path / "out")
        for f in findings:
            assert isinstance(f, Finding)

    def test_findings_source_is_ghidra_binary(self, tmp_path):
        fake_analyzer = _make_fake_analyzer()
        analyzer = BinaryAnalyzer(ghidra_analyzer=fake_analyzer)

        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x4d\x5a\x90\x00")

        findings = analyzer.analyze(binary, tmp_path / "out")
        for f in findings:
            assert f.source == "ghidra_binary"

    def test_finding_file_path_matches_binary(self, tmp_path):
        fake_analyzer = _make_fake_analyzer()
        analyzer = BinaryAnalyzer(ghidra_analyzer=fake_analyzer)

        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x4d\x5a\x90\x00")

        findings = analyzer.analyze(binary, tmp_path / "out")
        for f in findings:
            assert f.file_path == str(binary)

    def test_ghidra_returns_none_raises_analysis_error(self, tmp_path):
        fake_analyzer = _make_fake_analyzer(results=None)
        analyzer = BinaryAnalyzer(ghidra_analyzer=fake_analyzer)

        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x4d\x5a\x90\x00")

        with pytest.raises(AnalysisError) as exc_info:
            analyzer.analyze(binary, tmp_path / "out")
        assert "failed" in exc_info.value.message.lower()


# ---------------------------------------------------------------------------
# _indicator_to_finding: conversion per category
# ---------------------------------------------------------------------------

class TestIndicatorToFinding:
    @pytest.fixture
    def analyzer(self, tmp_path):
        fake_analyzer = _make_fake_analyzer()
        return BinaryAnalyzer(ghidra_analyzer=fake_analyzer)

    @pytest.fixture
    def binary_path(self, tmp_path):
        p = tmp_path / "sample.exe"
        p.write_bytes(b"\x4d\x5a")
        return p

    def test_suspicious_section_high_confidence(self, analyzer, binary_path):
        indicator = {
            "type": "suspicious_section",
            "value": ".rwx",
            "description": "Section .rwx has RWX permissions",
            "severity": "high",
        }
        f = analyzer._indicator_to_finding(indicator, binary_path)
        assert f.category == "suspicious_section"
        assert f.severity == "high"
        assert f.confidence == "high"
        assert f.location == ".rwx"
        assert f.source == "ghidra_binary"

    def test_suspicious_import_medium_confidence(self, analyzer, binary_path):
        indicator = {
            "type": "suspicious_import",
            "value": "VirtualAlloc",
            "description": "Potentially suspicious API import: VirtualAlloc",
            "severity": "medium",
        }
        f = analyzer._indicator_to_finding(indicator, binary_path)
        assert f.category == "suspicious_import"
        assert f.severity == "medium"
        assert f.confidence == "medium"
        assert f.location == "VirtualAlloc"

    def test_suspicious_string_low_confidence(self, analyzer, binary_path):
        indicator = {
            "type": "suspicious_string",
            "value": "http://example.com",
            "description": "URL string found",
            "severity": "low",
        }
        f = analyzer._indicator_to_finding(indicator, binary_path)
        assert f.category == "suspicious_string"
        assert f.severity == "low"
        assert f.confidence == "low"

    def test_evidence_contains_raw_indicator(self, analyzer, binary_path):
        indicator = {
            "type": "suspicious_import",
            "value": "WinExec",
            "description": "Potentially suspicious API import: WinExec",
            "severity": "medium",
        }
        f = analyzer._indicator_to_finding(indicator, binary_path)
        assert f.evidence["type"] == "suspicious_import"
        assert f.evidence["value"] == "WinExec"

    def test_finding_id_is_16_hex_chars(self, analyzer, binary_path):
        indicator = {
            "type": "suspicious_string",
            "value": "password",
            "description": "Password-related string",
            "severity": "low",
        }
        f = analyzer._indicator_to_finding(indicator, binary_path)
        assert len(f.finding_id) == 16
        assert all(c in "0123456789abcdef" for c in f.finding_id)

    def test_empty_value_gives_none_location(self, analyzer, binary_path):
        indicator = {
            "type": "suspicious_import",
            "value": "",
            "description": "Empty value test",
            "severity": "medium",
        }
        f = analyzer._indicator_to_finding(indicator, binary_path)
        assert f.location is None

    def test_unknown_indicator_type_falls_back_to_low_confidence(self, analyzer, binary_path):
        indicator = {
            "type": "unknown_type",
            "value": "something",
            "description": "Unknown indicator type",
            "severity": "low",
        }
        f = analyzer._indicator_to_finding(indicator, binary_path)
        assert f.confidence == "low"
