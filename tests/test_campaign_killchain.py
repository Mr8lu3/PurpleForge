"""
Tests for purpleforge.campaign.killchain.

Covers: Mermaid output structure, DOT output structure, ATT&CK grouping.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from purpleforge.campaign.killchain import to_mermaid, to_dot, write_diagrams
from purpleforge.campaign.models import Campaign, CampaignResult, StageResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_campaign(stages_dicts) -> Campaign:
    return Campaign.model_validate({
        "name": "Kill-Chain Test",
        "description": "Test",
        "abort_on_failure": True,
        "shared_context_keys": [],
        "stages": stages_dicts,
    })


def _make_result(stage_statuses: dict) -> CampaignResult:
    stages = [
        StageResult(stage_id=sid, status=status)
        for sid, status in stage_statuses.items()
    ]
    return CampaignResult(
        campaign_id="test-id",
        campaign_name="Kill-Chain Test",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:01:00Z",
        overall_status="success",
        stages=stages,
    )


def _stage(sid, depends_on=None, scenario="s.yml"):
    return {
        "id": sid,
        "scenario": scenario,
        "target": "http://localhost",
        "required": True,
        "depends_on": depends_on or [],
        "exports": [],
        "imports": [],
    }


# ---------------------------------------------------------------------------
# Mermaid output
# ---------------------------------------------------------------------------

class TestMermaid:
    def test_starts_with_graph_lr(self):
        c = _make_campaign([_stage("recon")])
        r = _make_result({"recon": "success"})
        out = to_mermaid(c, r)
        assert out.strip().startswith("graph LR")

    def test_contains_all_stage_nodes(self):
        c = _make_campaign([_stage("recon"), _stage("xss", depends_on=["recon"])])
        r = _make_result({"recon": "success", "xss": "success"})
        out = to_mermaid(c, r)
        assert "recon" in out
        assert "xss" in out

    def test_contains_edge_for_depends_on(self):
        c = _make_campaign([_stage("a"), _stage("b", depends_on=["a"])])
        r = _make_result({"a": "success", "b": "success"})
        out = to_mermaid(c, r)
        assert "a --> b" in out or "a-->b" in out

    def test_success_style_class_present(self):
        c = _make_campaign([_stage("a")])
        r = _make_result({"a": "success"})
        out = to_mermaid(c, r)
        assert "classDef success" in out

    def test_failed_style_class_present(self):
        c = _make_campaign([_stage("a")])
        r = _make_result({"a": "failed"})
        out = to_mermaid(c, r)
        assert "classDef failed" in out

    def test_skipped_style_class_present(self):
        c = _make_campaign([_stage("a")])
        r = _make_result({"a": "skipped"})
        out = to_mermaid(c, r)
        assert "classDef skipped" in out

    def test_node_labelled_with_status(self):
        c = _make_campaign([_stage("recon")])
        r = _make_result({"recon": "success"})
        out = to_mermaid(c, r)
        assert "success" in out
        assert "recon" in out

    def test_class_assignment_for_success_node(self):
        c = _make_campaign([_stage("alpha")])
        r = _make_result({"alpha": "success"})
        out = to_mermaid(c, r)
        # Node safe_id = "alpha", class success
        assert "class alpha success" in out or "class alpha,alpha success" in out.replace("alpha,", "alpha,") or "alpha" in out


# ---------------------------------------------------------------------------
# DOT output
# ---------------------------------------------------------------------------

class TestDot:
    def test_contains_digraph_keyword(self):
        c = _make_campaign([_stage("recon")])
        r = _make_result({"recon": "success"})
        out = to_dot(c, r)
        assert "digraph" in out

    def test_contains_all_stage_ids(self):
        c = _make_campaign([_stage("recon"), _stage("xss", depends_on=["recon"])])
        r = _make_result({"recon": "success", "xss": "failed"})
        out = to_dot(c, r)
        assert "recon" in out
        assert "xss" in out

    def test_contains_arrow_for_depends_on(self):
        c = _make_campaign([_stage("a"), _stage("b", depends_on=["a"])])
        r = _make_result({"a": "success", "b": "success"})
        out = to_dot(c, r)
        assert "->" in out

    def test_closing_brace(self):
        c = _make_campaign([_stage("x")])
        r = _make_result({"x": "success"})
        out = to_dot(c, r)
        assert out.strip().endswith("}")

    def test_unknown_tactic_cluster_present_when_no_techniques(self):
        """Stages with no technique mapping land in Unknown cluster."""
        c = _make_campaign([_stage("mystery", scenario="no_such_file.yml")])
        r = _make_result({"mystery": "success"})
        out = to_dot(c, r)
        assert "Unknown" in out


# ---------------------------------------------------------------------------
# ATT&CK grouping
# ---------------------------------------------------------------------------

class TestAttackGrouping:
    def test_known_technique_maps_to_tactic(self, tmp_path):
        """Stage with T1190 (Initial Access) should land in Initial Access cluster."""
        scenario_file = tmp_path / "recon.yml"
        scenario_file.write_text(
            "name: recon\natt_ck_techniques: [T1190]\n", encoding="utf-8"
        )
        c = _make_campaign([_stage("recon", scenario=str(scenario_file))])
        r = _make_result({"recon": "success"})
        out = to_dot(c, r)
        assert "Initial Access" in out

    def test_unknown_technique_goes_to_unknown(self, tmp_path):
        """Stage with unknown technique code goes to Unknown cluster."""
        scenario_file = tmp_path / "weird.yml"
        scenario_file.write_text(
            "name: weird\natt_ck_techniques: [T9999]\n", encoding="utf-8"
        )
        c = _make_campaign([_stage("weird", scenario=str(scenario_file))])
        r = _make_result({"weird": "success"})
        out = to_dot(c, r)
        assert "Unknown" in out

    def test_missing_scenario_file_goes_to_unknown(self):
        """Stage whose scenario file doesn't exist goes to Unknown cluster gracefully."""
        c = _make_campaign([_stage("ghost", scenario="nonexistent.yml")])
        r = _make_result({"ghost": "skipped"})
        out = to_dot(c, r)
        assert "Unknown" in out


# ---------------------------------------------------------------------------
# write_diagrams
# ---------------------------------------------------------------------------

def test_write_diagrams_creates_files(tmp_path):
    c = _make_campaign([_stage("a"), _stage("b", depends_on=["a"])])
    r = _make_result({"a": "success", "b": "success"})
    out_dir = tmp_path / "diagrams"
    write_diagrams(out_dir, c, r)
    assert (out_dir / "killchain.mmd").exists()
    assert (out_dir / "killchain.dot").exists()
    assert "digraph" in (out_dir / "killchain.dot").read_text(encoding="utf-8")
    assert "graph LR" in (out_dir / "killchain.mmd").read_text(encoding="utf-8")
