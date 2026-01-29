"""Tests for scenario validation."""

import pytest
from pathlib import Path
from pydantic import ValidationError

from purpleforge.scenarios.models import (
    Scenario,
    ScenarioStep,
    Target,
    TargetType,
    ScenarioCategory,
    ScenarioMode,
)


def test_valid_scenario():
    """Test valid scenario creation."""
    scenario = Scenario(
        name="Test Scenario",
        description="Test description",
        category=ScenarioCategory.WEB,
        mode=ScenarioMode.ASSESS,
        target=Target(type=TargetType.WEB, base_url="http://example.com"),
        steps=[
            ScenarioStep(
                id="step1",
                type="http_get_baseline",
                description="Test step",
                parameters={"path": "/"},
            )
        ],
    )

    assert scenario.name == "Test Scenario"
    assert len(scenario.steps) == 1


def test_web_target_requires_base_url():
    """Test that web targets require base_url."""
    with pytest.raises(ValidationError):
        Target(type=TargetType.WEB)  # Missing base_url


def test_unique_step_ids():
    """Test that step IDs must be unique."""
    with pytest.raises(ValidationError):
        Scenario(
            name="Test",
            description="Test",
            category=ScenarioCategory.WEB,
            target=Target(type=TargetType.WEB, base_url="http://example.com"),
            steps=[
                ScenarioStep(
                    id="duplicate",
                    type="test",
                    description="Step 1",
                ),
                ScenarioStep(
                    id="duplicate",
                    type="test",
                    description="Step 2",
                ),
            ],
        )


def test_step_timeout_validation():
    """Test that step timeout is validated."""
    # Valid timeout
    step = ScenarioStep(
        id="test",
        type="test",
        description="Test",
        timeout_seconds=30,
    )
    assert step.timeout_seconds == 30

    # Invalid timeout (too large)
    with pytest.raises(ValidationError):
        ScenarioStep(
            id="test",
            type="test",
            description="Test",
            timeout_seconds=500,
        )
