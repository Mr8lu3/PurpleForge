"""Tests for analyze-binary CLI command."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from purpleforge.cli.main import app
from purpleforge.utils.exceptions import AnalysisError

runner = CliRunner()


def _create_binary(tmp_path: Path, name: str = "sample.exe") -> Path:
    """Write a minimal dummy binary file."""
    p = tmp_path / name
    p.write_bytes(b"\x4d\x5a\x90\x00")
    return p


class TestAnalyzeBinaryHelp:
    def test_help_succeeds(self):
        result = runner.invoke(app, ["analyze-binary", "--help"])
        assert result.exit_code == 0

    def test_help_contains_defensive_note(self):
        result = runner.invoke(app, ["analyze-binary", "--help"])
        output = result.stdout
        assert "defensive" in output.lower() or "authorized" in output.lower()

    def test_help_contains_precedence_note(self):
        result = runner.invoke(app, ["analyze-binary", "--help"])
        output = result.stdout
        assert "precedence" in output.lower() or "run-id" in output.lower()


class TestAnalyzeBinaryGhidraUnavailable:
    def test_exits_nonzero_when_ghidra_unavailable(self, tmp_path):
        binary = _create_binary(tmp_path)
        with patch(
            "purpleforge.analysis.binary_analyzer.BinaryAnalyzer.analyze",
            side_effect=AnalysisError("Ghidra not available", hint="Set GHIDRA_HOME"),
        ):
            result = runner.invoke(app, ["analyze-binary", str(binary)])

        assert result.exit_code != 0

    def test_error_message_in_output(self, tmp_path):
        binary = _create_binary(tmp_path)
        with patch(
            "purpleforge.analysis.binary_analyzer.BinaryAnalyzer.analyze",
            side_effect=AnalysisError("Ghidra not available", hint="Set GHIDRA_HOME"),
        ):
            result = runner.invoke(app, ["analyze-binary", str(binary)])

        combined = result.stdout + (result.stderr or "")
        assert "Ghidra not available" in combined

    def test_hint_in_output(self, tmp_path):
        binary = _create_binary(tmp_path)
        with patch(
            "purpleforge.analysis.binary_analyzer.BinaryAnalyzer.analyze",
            side_effect=AnalysisError("Ghidra not available", hint="Set GHIDRA_HOME"),
        ):
            result = runner.invoke(app, ["analyze-binary", str(binary)])

        combined = result.stdout + (result.stderr or "")
        assert "Hint:" in combined or "GHIDRA_HOME" in combined

    def test_no_traceback_in_output(self, tmp_path):
        binary = _create_binary(tmp_path)
        with patch(
            "purpleforge.analysis.binary_analyzer.BinaryAnalyzer.analyze",
            side_effect=AnalysisError("Ghidra not available", hint="Set GHIDRA_HOME"),
        ):
            result = runner.invoke(app, ["analyze-binary", str(binary)])

        combined = result.stdout + (result.stderr or "")
        assert "Traceback" not in combined


class TestAnalyzeBinarySuccess:
    def _mock_findings(self):
        from purpleforge.analysis.findings_schema import Finding
        return [
            Finding(
                source="ghidra_binary",
                category="suspicious_import",
                title="Suspicious import: VirtualAlloc",
                description="Potentially suspicious API import: VirtualAlloc",
                severity="medium",
                confidence="medium",
                location="VirtualAlloc",
            )
        ]

    def test_exits_zero_on_success(self, tmp_path):
        binary = _create_binary(tmp_path)
        out_dir = tmp_path / "out"
        with patch(
            "purpleforge.analysis.binary_analyzer.BinaryAnalyzer.analyze",
            return_value=self._mock_findings(),
        ):
            result = runner.invoke(
                app,
                ["analyze-binary", str(binary), "--output", str(out_dir)],
            )
        assert result.exit_code == 0

    def test_output_contains_summary_table(self, tmp_path):
        binary = _create_binary(tmp_path)
        out_dir = tmp_path / "out"
        with patch(
            "purpleforge.analysis.binary_analyzer.BinaryAnalyzer.analyze",
            return_value=self._mock_findings(),
        ):
            result = runner.invoke(
                app,
                ["analyze-binary", str(binary), "--output", str(out_dir)],
            )
        assert "Severity" in result.stdout or "medium" in result.stdout

    def test_run_id_missing_dir_exits_nonzero(self, tmp_path):
        binary = _create_binary(tmp_path)
        result = runner.invoke(
            app,
            ["analyze-binary", str(binary), "--run-id", "nonexistent-run-id-12345"],
        )
        assert result.exit_code != 0
