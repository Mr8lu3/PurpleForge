"""
Tests for CampaignRunner.

Uses monkeypatching of execute_scenario to avoid real HTTP calls.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from purpleforge.campaign.models import Campaign, CampaignResult, StageStatus
from purpleforge.campaign.runner import CampaignRunner


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

def _stage_dict(sid: str, depends_on=None, required=True, exports=None):
    return {
        "id": sid,
        "scenario": "scenarios/test.yml",
        "target": "http://localhost:8080",
        "required": required,
        "depends_on": depends_on or [],
        "exports": exports or [],
        "imports": [],
    }


def _campaign_dict(stages, abort_on_failure=True):
    return {
        "name": "Runner Test Campaign",
        "description": "Test",
        "abort_on_failure": abort_on_failure,
        "shared_context_keys": [],
        "stages": stages,
    }


def _make_fake_run_dir(tmp_path: Path, run_id: str | None = None) -> Path:
    """Create a fake run_dir that execute_scenario would normally return."""
    rid = run_id or str(uuid.uuid4())
    run_dir = tmp_path / "runs" / rid
    run_dir.mkdir(parents=True, exist_ok=True)

    # meta.json
    (run_dir / "meta.json").write_text(
        json.dumps({"run_id": rid, "status": "completed"}), encoding="utf-8"
    )

    # correlation/coverage.json
    correlation = run_dir / "correlation"
    correlation.mkdir(exist_ok=True)
    (correlation / "coverage.json").write_text(
        json.dumps({
            "total_steps": 1,
            "steps_with_evidence": 1,
            "coverage_percentage": 100.0,
            "baseline_status": 200,
        }),
        encoding="utf-8",
    )
    return run_dir


# ---------------------------------------------------------------------------
# 3-stage linear campaign
# ---------------------------------------------------------------------------

def test_three_stage_linear_executes_in_order(tmp_path):
    """Stages a -> b -> c run in that order."""
    execution_order: List[str] = []

    def fake_execute(scenario_path, target, workspace_dir, **kwargs):
        # Determine which stage is being run by the scenario path (all same here),
        # so we track by side-effect counter instead.
        run_dir = _make_fake_run_dir(tmp_path)
        execution_order.append(str(scenario_path))
        return run_dir

    campaign = Campaign.model_validate(_campaign_dict([
        _stage_dict("a"),
        _stage_dict("b", depends_on=["a"]),
        _stage_dict("c", depends_on=["b"]),
    ]))

    runner = CampaignRunner(campaign, tmp_path, base_dir=tmp_path)

    with patch("purpleforge.campaign.runner.execute_scenario", side_effect=fake_execute):
        result = runner.execute()

    assert len(result.stages) == 3
    assert [sr.stage_id for sr in result.stages] == ["a", "b", "c"]
    assert all(sr.status == StageStatus.SUCCESS for sr in result.stages)
    assert result.overall_status == "success"


def test_stages_execute_in_dependency_order(tmp_path):
    """With a diamond, leaf must run after both branches."""
    order: List[str] = []

    def fake_execute(scenario_path, target, workspace_dir, **kwargs):
        return _make_fake_run_dir(tmp_path)

    campaign = Campaign.model_validate(_campaign_dict([
        _stage_dict("root"),
        _stage_dict("left", depends_on=["root"]),
        _stage_dict("right", depends_on=["root"]),
        _stage_dict("leaf", depends_on=["left", "right"]),
    ]))

    runner = CampaignRunner(campaign, tmp_path, base_dir=tmp_path)
    call_order: List[str] = []

    original = __import__("purpleforge.campaign.runner", fromlist=["execute_scenario"])

    def tracking_execute(scenario_path, target, workspace_dir, **kwargs):
        # We can't distinguish stages by scenario path here, so we rely on
        # topological_order being deterministic.
        return _make_fake_run_dir(tmp_path)

    with patch("purpleforge.campaign.runner.execute_scenario", side_effect=tracking_execute):
        result = runner.execute()

    assert result.stages[0].stage_id == "root"
    assert result.stages[-1].stage_id == "leaf"


# ---------------------------------------------------------------------------
# Required-stage failure aborts downstream
# ---------------------------------------------------------------------------

def test_required_stage_failure_aborts_downstream(tmp_path):
    """When required stage 'a' fails and abort_on_failure=True, b is skipped."""
    call_count = {"n": 0}

    def fake_execute(scenario_path, target, workspace_dir, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("Simulated failure")
        return _make_fake_run_dir(tmp_path)

    campaign = Campaign.model_validate(_campaign_dict([
        _stage_dict("a", required=True),
        _stage_dict("b", depends_on=["a"]),
    ], abort_on_failure=True))

    runner = CampaignRunner(campaign, tmp_path, base_dir=tmp_path)

    with patch("purpleforge.campaign.runner.execute_scenario", side_effect=fake_execute):
        result = runner.execute()

    stage_by_id = {sr.stage_id: sr for sr in result.stages}
    assert stage_by_id["a"].status == StageStatus.FAILED
    assert stage_by_id["b"].status == StageStatus.SKIPPED
    assert result.overall_status == "aborted"


def test_required_failure_no_abort_continues(tmp_path):
    """When abort_on_failure=False, even required stage failure does not stop next stage."""
    call_count = {"n": 0}

    def fake_execute(scenario_path, target, workspace_dir, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("Simulated failure")
        return _make_fake_run_dir(tmp_path)

    campaign = Campaign.model_validate(_campaign_dict([
        _stage_dict("a", required=True),
        _stage_dict("b"),  # no depends_on -> should still run
    ], abort_on_failure=False))

    runner = CampaignRunner(campaign, tmp_path, base_dir=tmp_path)

    with patch("purpleforge.campaign.runner.execute_scenario", side_effect=fake_execute):
        result = runner.execute()

    stage_by_id = {sr.stage_id: sr for sr in result.stages}
    assert stage_by_id["a"].status == StageStatus.FAILED
    # b has no depends_on, so it runs regardless
    assert stage_by_id["b"].status == StageStatus.SUCCESS


# ---------------------------------------------------------------------------
# Non-required failure does not abort
# ---------------------------------------------------------------------------

def test_non_required_stage_failure_does_not_abort(tmp_path):
    """A non-required stage failing should not stop subsequent stages."""
    call_count = {"n": 0}

    def fake_execute(scenario_path, target, workspace_dir, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("optional stage error")
        return _make_fake_run_dir(tmp_path)

    campaign = Campaign.model_validate(_campaign_dict([
        _stage_dict("optional", required=False),
        _stage_dict("required_stage"),  # no dependency on optional
    ]))

    runner = CampaignRunner(campaign, tmp_path, base_dir=tmp_path)

    with patch("purpleforge.campaign.runner.execute_scenario", side_effect=fake_execute):
        result = runner.execute()

    stage_by_id = {sr.stage_id: sr for sr in result.stages}
    assert stage_by_id["optional"].status == StageStatus.FAILED
    assert stage_by_id["required_stage"].status == StageStatus.SUCCESS


# ---------------------------------------------------------------------------
# Campaign artifacts written
# ---------------------------------------------------------------------------

def test_campaign_json_written(tmp_path):
    """campaign.json must exist under campaigns/<id>/ after execution."""
    def fake_execute(scenario_path, target, workspace_dir, **kwargs):
        return _make_fake_run_dir(tmp_path)

    campaign = Campaign.model_validate(_campaign_dict([_stage_dict("only")]))
    runner = CampaignRunner(campaign, tmp_path, base_dir=tmp_path)

    with patch("purpleforge.campaign.runner.execute_scenario", side_effect=fake_execute):
        result = runner.execute()

    campaign_json = runner.campaign_dir / "campaign.json"
    assert campaign_json.exists()
    data = json.loads(campaign_json.read_text(encoding="utf-8"))
    assert "campaign" in data
    assert "result" in data


def test_campaign_log_jsonl_written(tmp_path):
    """campaign.log.jsonl must contain at least started/completed events."""
    def fake_execute(scenario_path, target, workspace_dir, **kwargs):
        return _make_fake_run_dir(tmp_path)

    campaign = Campaign.model_validate(_campaign_dict([_stage_dict("only")]))
    runner = CampaignRunner(campaign, tmp_path, base_dir=tmp_path)

    with patch("purpleforge.campaign.runner.execute_scenario", side_effect=fake_execute):
        runner.execute()

    log_path = runner.campaign_dir / "campaign.log.jsonl"
    assert log_path.exists()
    lines = [json.loads(l) for l in log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    events = [l["event"] for l in lines]
    assert "campaign_started" in events
    assert "campaign_completed" in events
