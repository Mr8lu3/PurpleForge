"""Tests for `purpleforge audit verify` CLI command."""

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from purpleforge.cli.main import app
from purpleforge.audit.hash_chain import HashChainLog


runner = CliRunner()


@pytest.fixture
def intact_run(tmp_path):
    """Create a minimal workspace run with a valid audit log."""
    # Minimal workspace structure expected by WorkspaceManager.get_run_dir
    ws = tmp_path / "workspace"
    ws.mkdir()

    run_id = "test-run-audit-cli"
    run_dir = ws / run_id
    run_dir.mkdir()

    # Write meta.json so WorkspaceManager recognises it
    (run_dir / "meta.json").write_text(
        json.dumps({
            "run_id": run_id,
            "tool_version": "0.8.0",
            "started_at": "2026-04-07T12:00:00",
            "completed_at": None,
            "status": "completed",
            "operator_acknowledgements": [],
            "target_verification": None,
            "scenario_hash": None,
            "config_hash": None,
            "platform": {},
        }),
        encoding="utf-8",
    )

    # Write audit log
    audit_dir = run_dir / "audit"
    audit_dir.mkdir()
    chain = HashChainLog(audit_dir / "run_audit.log.jsonl")
    chain.append({"event": "run_created", "ts": "2026-04-07T12:00:00+00:00", "run_id": run_id})
    chain.append({"event": "run_completed", "ts": "2026-04-07T12:01:00+00:00", "status": "completed"})

    return ws, run_id


@pytest.fixture
def tampered_run(tmp_path):
    """Create a workspace run with a tampered audit log."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    run_id = "test-run-tampered"
    run_dir = ws / run_id
    run_dir.mkdir()

    (run_dir / "meta.json").write_text(
        json.dumps({
            "run_id": run_id,
            "tool_version": "0.8.0",
            "started_at": "2026-04-07T12:00:00",
            "completed_at": None,
            "status": "completed",
            "operator_acknowledgements": [],
            "target_verification": None,
            "scenario_hash": None,
            "config_hash": None,
            "platform": {},
        }),
        encoding="utf-8",
    )

    audit_dir = run_dir / "audit"
    audit_dir.mkdir()
    log_path = audit_dir / "run_audit.log.jsonl"
    chain = HashChainLog(log_path)
    chain.append({"event": "run_created", "ts": "2026-04-07T12:00:00+00:00"})
    chain.append({"event": "step_started", "ts": "2026-04-07T12:00:01+00:00"})
    chain.append({"event": "run_completed", "ts": "2026-04-07T12:01:00+00:00"})

    # Tamper entry at seq=1
    lines = log_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["payload"]["tampered"] = True
    lines[1] = json.dumps(entry)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return ws, run_id


class TestAuditVerifyCLI:

    def test_intact_exit_code_0(self, intact_run):
        ws, run_id = intact_run
        result = runner.invoke(
            app,
            ["audit", "verify", run_id, "--workspace", str(ws)],
        )
        assert result.exit_code == 0, result.output
        assert "INTACT" in result.output

    def test_intact_output_has_chain_length(self, intact_run):
        ws, run_id = intact_run
        result = runner.invoke(
            app,
            ["audit", "verify", run_id, "--workspace", str(ws)],
        )
        assert "Chain length" in result.output or "2" in result.output

    def test_tampered_exit_code_2(self, tampered_run):
        ws, run_id = tampered_run
        result = runner.invoke(
            app,
            ["audit", "verify", run_id, "--workspace", str(ws)],
        )
        assert result.exit_code == 2, result.output
        assert "TAMPERED" in result.output or "tampered" in result.output.lower()

    def test_tampered_no_traceback(self, tampered_run):
        ws, run_id = tampered_run
        result = runner.invoke(
            app,
            ["audit", "verify", run_id, "--workspace", str(ws)],
        )
        assert "Traceback" not in result.output

    def test_missing_run_exit_code_1(self, tmp_path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        result = runner.invoke(
            app,
            ["audit", "verify", "nonexistent-run-id", "--workspace", str(ws)],
        )
        assert result.exit_code == 1, result.output
        assert "Traceback" not in result.output

    def test_missing_audit_log_exit_code_1(self, tmp_path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        run_id = "no-audit-log-run"
        run_dir = ws / run_id
        run_dir.mkdir()
        (run_dir / "meta.json").write_text(
            json.dumps({
                "run_id": run_id,
                "tool_version": "0.8.0",
                "started_at": "2026-04-07T12:00:00",
                "completed_at": None,
                "status": "completed",
                "operator_acknowledgements": [],
                "target_verification": None,
                "scenario_hash": None,
                "config_hash": None,
                "platform": {},
            }),
            encoding="utf-8",
        )
        # No audit dir / log
        result = runner.invoke(
            app,
            ["audit", "verify", run_id, "--workspace", str(ws)],
        )
        assert result.exit_code == 1, result.output
        assert "Traceback" not in result.output

    def test_no_traceback_on_any_error(self, tmp_path):
        """All error paths must produce friendly messages, not raw tracebacks."""
        ws = tmp_path / "workspace"
        ws.mkdir()
        for case_run_id in ["totally-missing", "also-missing"]:
            result = runner.invoke(
                app,
                ["audit", "verify", case_run_id, "--workspace", str(ws)],
            )
            assert "Traceback" not in result.output
