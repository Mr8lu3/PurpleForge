"""
Tests for purpleforge.campaign.models.

Covers: valid load, duplicate id rejection, cycle rejection,
missing scenario file, topological sort determinism (diamond DAG).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from purpleforge.campaign.models import Campaign, CampaignStage
from purpleforge.utils.exceptions import CampaignError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_stage(sid: str, depends_on=None, scenario="scenarios/s.yml") -> dict:
    return {
        "id": sid,
        "scenario": scenario,
        "target": "http://localhost:8080",
        "required": True,
        "depends_on": depends_on or [],
        "exports": [],
        "imports": [],
    }


def _campaign_dict(**kwargs) -> dict:
    base = {
        "name": "Test Campaign",
        "description": "Test",
        "abort_on_failure": True,
        "shared_context_keys": [],
        "stages": [],
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Valid campaign
# ---------------------------------------------------------------------------

def test_valid_campaign_loads():
    data = _campaign_dict(stages=[
        _make_stage("recon"),
        _make_stage("xss", depends_on=["recon"]),
    ])
    c = Campaign.model_validate(data)
    assert c.name == "Test Campaign"
    assert len(c.stages) == 2


def test_single_stage_campaign():
    data = _campaign_dict(stages=[_make_stage("only")])
    c = Campaign.model_validate(data)
    assert len(c.stages) == 1


# ---------------------------------------------------------------------------
# Duplicate stage id
# ---------------------------------------------------------------------------

def test_duplicate_stage_id_rejected():
    data = _campaign_dict(stages=[
        _make_stage("a"),
        _make_stage("a"),
    ])
    with pytest.raises(CampaignError, match="Duplicate stage ids"):
        Campaign.model_validate(data)


# ---------------------------------------------------------------------------
# Missing depends_on reference
# ---------------------------------------------------------------------------

def test_missing_depends_on_reference_rejected():
    data = _campaign_dict(stages=[
        _make_stage("b", depends_on=["nonexistent"]),
    ])
    with pytest.raises(CampaignError, match="unknown stage"):
        Campaign.model_validate(data)


# ---------------------------------------------------------------------------
# Cycle detection
# ---------------------------------------------------------------------------

def test_direct_cycle_rejected():
    # a depends on b, b depends on a
    data = _campaign_dict(stages=[
        _make_stage("a", depends_on=["b"]),
        _make_stage("b", depends_on=["a"]),
    ])
    with pytest.raises(CampaignError, match="cycle"):
        Campaign.model_validate(data)


def test_self_cycle_rejected():
    data = _campaign_dict(stages=[
        _make_stage("a", depends_on=["a"]),
    ])
    with pytest.raises(CampaignError, match="cycle"):
        Campaign.model_validate(data)


def test_three_node_cycle_rejected():
    data = _campaign_dict(stages=[
        _make_stage("a", depends_on=["c"]),
        _make_stage("b", depends_on=["a"]),
        _make_stage("c", depends_on=["b"]),
    ])
    with pytest.raises(CampaignError, match="cycle"):
        Campaign.model_validate(data)


# ---------------------------------------------------------------------------
# Missing scenario file
# ---------------------------------------------------------------------------

def test_missing_scenario_file_raises_friendly_error(tmp_path):
    data = _campaign_dict(stages=[
        _make_stage("recon", scenario="does_not_exist.yml"),
    ])
    c = Campaign.model_validate(data)  # structural checks pass
    with pytest.raises(CampaignError, match="missing scenario file"):
        c.validate_scenario_files(base_dir=tmp_path)


def test_existing_scenario_file_passes(tmp_path):
    scenario_file = tmp_path / "s.yml"
    scenario_file.write_text("name: s\n")
    data = _campaign_dict(stages=[
        _make_stage("recon", scenario="s.yml"),
    ])
    c = Campaign.model_validate(data)
    # Should not raise.
    c.validate_scenario_files(base_dir=tmp_path)


# ---------------------------------------------------------------------------
# Topological sort — diamond DAG
# ---------------------------------------------------------------------------

def test_topological_sort_diamond():
    """
    Diamond: root -> left, root -> right, left -> leaf, right -> leaf
    Valid orders: [root, left, right, leaf] or [root, right, left, leaf]
    """
    data = _campaign_dict(stages=[
        _make_stage("root"),
        _make_stage("left", depends_on=["root"]),
        _make_stage("right", depends_on=["root"]),
        _make_stage("leaf", depends_on=["left", "right"]),
    ])
    c = Campaign.model_validate(data)
    order = [s.id for s in c.topological_order()]
    assert order[0] == "root"
    assert order[-1] == "leaf"
    assert set(order) == {"root", "left", "right", "leaf"}
    # leaf must come after both left and right
    assert order.index("leaf") > order.index("left")
    assert order.index("leaf") > order.index("right")


def test_topological_sort_is_deterministic():
    """Same YAML repeated twice must produce identical order."""
    data = _campaign_dict(stages=[
        _make_stage("a"),
        _make_stage("b", depends_on=["a"]),
        _make_stage("c", depends_on=["a"]),
        _make_stage("d", depends_on=["b", "c"]),
    ])
    c1 = Campaign.model_validate(data)
    c2 = Campaign.model_validate(data)
    assert [s.id for s in c1.topological_order()] == [s.id for s in c2.topological_order()]


def test_linear_chain_topological_order():
    data = _campaign_dict(stages=[
        _make_stage("a"),
        _make_stage("b", depends_on=["a"]),
        _make_stage("c", depends_on=["b"]),
    ])
    c = Campaign.model_validate(data)
    order = [s.id for s in c.topological_order()]
    assert order == ["a", "b", "c"]
