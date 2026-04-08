"""
Tests for the `purpleforge campaign` CLI command.

Uses Typer CliRunner with monkeypatched CampaignRunner so no real
scenario execution occurs.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from purpleforge.cli.main import app
from purpleforge.campaign.models import CampaignResult, StageResult

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_campaign_yaml(path: Path, stages: list) -> None:
    data = {
        "name": "CLI Test Campaign",
        "description": "Integration test campaign",
        "abort_on_failure": True,
        "shared_context_keys": [],
        "stages": stages,
    }
    path.write_text(yaml.dump(data), encoding="utf-8")


def _write_scenario_yaml(path: Path) -> None:
    data = {
        "name": "Test Scenario",
        "description": "Test",
        "category": "web",
        "target": {"type": "web", "base_url": "http://localhost:8080"},
        "steps": [],
    }
    path.write_text(yaml.dump(data), encoding="utf-8")


def _make_result(stage_ids: list, status: str = "success") -> CampaignResult:
    return CampaignResult(
        campaign_id=str(uuid.uuid4()),
        campaign_name="CLI Test Campaign",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:01:00Z",
        overall_status=status,
        stages=[
            StageResult(
                stage_id=sid,
                run_id=str(uuid.uuid4()),
                status="success",
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:30Z",
            )
            for sid in stage_ids
        ],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_campaign_command_exit_zero(tmp_path):
    """campaign command exits 0 when CampaignRunner returns success."""
    scenario_file = tmp_path / "s.yml"
    _write_scenario_yaml(scenario_file)

    campaign_file = tmp_path / "campaign.yml"
    _write_campaign_yaml(campaign_file, [
        {
            "id": "recon",
            "scenario": str(scenario_file),
            "target": "http://localhost:8080",
            "required": True,
            "depends_on": [],
            "exports": [],
            "imports": [],
        }
    ])

    fake_result = _make_result(["recon"])

    with patch("purpleforge.campaign.runner.CampaignRunner.execute", return_value=fake_result), \
         patch("purpleforge.campaign.killchain.write_diagrams"):
        result = runner.invoke(app, ["campaign", str(campaign_file), "--workspace", str(tmp_path)])

    assert result.exit_code == 0, result.output


def test_campaign_command_shows_stage_table(tmp_path):
    """campaign command prints stage names in console output."""
    scenario_file = tmp_path / "s.yml"
    _write_scenario_yaml(scenario_file)

    campaign_file = tmp_path / "campaign.yml"
    _write_campaign_yaml(campaign_file, [
        {
            "id": "alpha_stage",
            "scenario": str(scenario_file),
            "target": "http://localhost:8080",
            "required": True,
            "depends_on": [],
            "exports": [],
            "imports": [],
        }
    ])

    fake_result = _make_result(["alpha_stage"])

    with patch("purpleforge.campaign.runner.CampaignRunner.execute", return_value=fake_result), \
         patch("purpleforge.campaign.killchain.write_diagrams"):
        result = runner.invoke(app, ["campaign", str(campaign_file), "--workspace", str(tmp_path)])

    assert "alpha_stage" in result.output


def test_campaign_command_artifacts_written(tmp_path):
    """campaign.json should be written after execution."""
    scenario_file = tmp_path / "s.yml"
    _write_scenario_yaml(scenario_file)

    campaign_file = tmp_path / "campaign.yml"
    _write_campaign_yaml(campaign_file, [
        {
            "id": "only",
            "scenario": str(scenario_file),
            "target": "http://localhost:8080",
            "required": True,
            "depends_on": [],
            "exports": [],
            "imports": [],
        }
    ])

    # We need a real CampaignRunner to write campaign.json, so we patch only
    # execute_scenario (the inner runner).
    from purpleforge.campaign.models import StageStatus

    def fake_execute(scenario_path, target, workspace_dir, **kwargs):
        import uuid as _uuid
        rid = str(_uuid.uuid4())
        run_dir = tmp_path / "runs" / rid
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "meta.json").write_text(json.dumps({"run_id": rid, "status": "completed"}))
        (run_dir / "correlation").mkdir(exist_ok=True)
        (run_dir / "correlation" / "coverage.json").write_text(
            json.dumps({"total_steps": 0, "steps_with_evidence": 0, "coverage_percentage": 0.0})
        )
        return run_dir

    with patch("purpleforge.campaign.runner.execute_scenario", side_effect=fake_execute):
        result = runner.invoke(app, ["campaign", str(campaign_file), "--workspace", str(tmp_path)])

    assert result.exit_code == 0, result.output
    # Find the campaign dir that was created.
    campaigns_dir = tmp_path / "campaigns"
    assert campaigns_dir.exists()
    campaign_dirs = list(campaigns_dir.iterdir())
    assert len(campaign_dirs) == 1
    assert (campaign_dirs[0] / "campaign.json").exists()


def test_campaign_command_aborted_exits_nonzero(tmp_path):
    """campaign command exits non-zero when overall_status is aborted."""
    scenario_file = tmp_path / "s.yml"
    _write_scenario_yaml(scenario_file)

    campaign_file = tmp_path / "campaign.yml"
    _write_campaign_yaml(campaign_file, [
        {
            "id": "fail_stage",
            "scenario": str(scenario_file),
            "target": "http://localhost:8080",
            "required": True,
            "depends_on": [],
            "exports": [],
            "imports": [],
        }
    ])

    fake_result = CampaignResult(
        campaign_id=str(uuid.uuid4()),
        campaign_name="CLI Test Campaign",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:01:00Z",
        overall_status="aborted",
        stages=[StageResult(stage_id="fail_stage", status="failed", error="boom")],
    )

    with patch("purpleforge.campaign.runner.CampaignRunner.execute", return_value=fake_result), \
         patch("purpleforge.campaign.killchain.write_diagrams"):
        result = runner.invoke(app, ["campaign", str(campaign_file), "--workspace", str(tmp_path)])

    assert result.exit_code != 0


def test_campaign_invalid_yaml_exits_nonzero(tmp_path):
    """Invalid campaign YAML exits with non-zero code and friendly error."""
    campaign_file = tmp_path / "bad.yml"
    campaign_file.write_text("not_a_campaign: [unclosed", encoding="utf-8")

    result = runner.invoke(app, ["campaign", str(campaign_file)])
    assert result.exit_code != 0
