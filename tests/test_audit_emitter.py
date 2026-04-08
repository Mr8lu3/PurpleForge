"""Tests for purpleforge.audit.events.AuditEmitter."""

import json
import pytest
from pathlib import Path

from purpleforge.audit.events import AuditEmitter
from purpleforge.audit.hash_chain import verify_log


@pytest.fixture
def run_dir(tmp_path):
    rd = tmp_path / "run-test"
    rd.mkdir()
    return rd


class TestAuditEmitter:

    def test_run_created_writes_entry(self, run_dir):
        emitter = AuditEmitter(run_dir)
        emitter.run_created("run-123", "My Scenario")

        log_path = run_dir / "audit" / "run_audit.log.jsonl"
        assert log_path.exists()
        lines = log_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["payload"]["event"] == "run_created"
        assert entry["payload"]["run_id"] == "run-123"

    def test_scenario_loaded_written(self, run_dir):
        emitter = AuditEmitter(run_dir)
        emitter.scenario_loaded("Test", "abc123")

        log_path = run_dir / "audit" / "run_audit.log.jsonl"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        assert entry["payload"]["event"] == "scenario_loaded"
        assert entry["payload"]["sha256"] == "abc123"

    def test_target_verified_written(self, run_dir):
        emitter = AuditEmitter(run_dir)
        emitter.target_verified("http://example.com")
        log_path = run_dir / "audit" / "run_audit.log.jsonl"
        entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
        assert entry["payload"]["event"] == "target_verified"

    def test_step_events_written(self, run_dir):
        emitter = AuditEmitter(run_dir)
        emitter.step_started("step-1")
        emitter.step_completed("step-1", "success")
        log_path = run_dir / "audit" / "run_audit.log.jsonl"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["payload"]["event"] == "step_started"
        assert json.loads(lines[1])["payload"]["event"] == "step_completed"
        assert json.loads(lines[1])["payload"]["status"] == "success"

    def test_run_completed_written(self, run_dir):
        emitter = AuditEmitter(run_dir)
        emitter.run_completed("completed", {"total": 3, "successful": 2, "failed": 1})
        log_path = run_dir / "audit" / "run_audit.log.jsonl"
        entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
        assert entry["payload"]["event"] == "run_completed"
        assert entry["payload"]["counts"]["total"] == 3

    def test_chain_verifies_after_multiple_events(self, run_dir):
        emitter = AuditEmitter(run_dir)
        emitter.run_created("run-1", "Scenario A")
        emitter.step_started("s1")
        emitter.step_completed("s1", "success")
        emitter.run_completed("completed")

        log_path = run_dir / "audit" / "run_audit.log.jsonl"
        ok, _ = verify_log(log_path)
        assert ok is True

    def test_failures_swallowed_not_raised(self, run_dir, monkeypatch):
        """If HashChainLog.append raises, AuditEmitter must NOT propagate."""
        emitter = AuditEmitter(run_dir)

        def bad_append(payload):
            raise RuntimeError("disk full simulation")

        monkeypatch.setattr(emitter._chain, "append", bad_append)

        # Must not raise
        emitter.run_created("run-x", "boom")
        emitter.step_started("s1")
        emitter.step_completed("s1", "failed")
        emitter.run_completed("failed")

    def test_audit_dir_created_if_missing(self, tmp_path):
        run_dir = tmp_path / "newrun"
        run_dir.mkdir()
        # audit subdir does NOT exist yet
        emitter = AuditEmitter(run_dir)
        emitter.run_created("r", "s")
        assert (run_dir / "audit" / "run_audit.log.jsonl").exists()
