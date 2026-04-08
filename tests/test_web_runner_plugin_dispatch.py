"""Tests for WebRunner plugin dispatch via StepPluginRegistry."""

import logging
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from purpleforge.runners.plugins import StepContext, registry
from purpleforge.scenarios.models import (
    Scenario,
    ScenarioCategory,
    ScenarioMode,
    ScenarioStep,
    Target,
    TargetType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def run_dir(tmp_path: Path) -> Path:
    """Create the expected WebRunner directory structure."""
    (tmp_path / "telemetry").mkdir()
    (tmp_path / "ground_truth").mkdir()
    return tmp_path


def _make_scenario(step_type: str, step_id: str = "s1") -> Scenario:
    return Scenario(
        name="Test Scenario",
        description="Plugin dispatch test",
        category=ScenarioCategory.WEB,
        mode=ScenarioMode.ASSESS,
        ownership_verification=False,
        target=Target(type=TargetType.WEB, base_url="http://testserver"),
        steps=[
            ScenarioStep(
                id=step_id,
                type=step_type,
                description="test step",
                continue_on_failure=True,
            )
        ],
    )


# ---------------------------------------------------------------------------
# Unknown step type: sets error, does NOT raise
# ---------------------------------------------------------------------------


def test_unknown_step_type_sets_error_no_raise(run_dir: Path) -> None:
    from purpleforge.runners.web import WebRunner

    scenario = _make_scenario("completely_unknown_type_xyz")

    # Reset the class-level flag so load_entry_points is called fresh each test.
    WebRunner._entry_points_loaded = False

    with WebRunner(
        scenario=scenario,
        run_dir=run_dir,
        base_url="http://testserver",
        timeout=5,
    ) as runner:
        step = scenario.steps[0]
        result = runner.execute_step(step)

    assert result["success"] is False
    assert "Unknown step type" in result["error"]
    assert "completely_unknown_type_xyz" in result["error"]
    # Registered types must be listed in the error message.
    assert "http_get_baseline" in result["error"]


# ---------------------------------------------------------------------------
# Dynamically registered handler: success=True, handler invoked
# ---------------------------------------------------------------------------


def test_dynamically_registered_handler_is_dispatched(run_dir: Path) -> None:
    from purpleforge.runners.web import WebRunner

    invoked: Dict[str, Any] = {}

    def fake_handler(
        step: ScenarioStep, result: Dict[str, Any], ctx: StepContext
    ) -> None:
        invoked["called"] = True
        invoked["base_url"] = ctx.base_url
        result["custom_key"] = "custom_value"

    # Register directly into the singleton used by WebRunner.
    registry.register("fake_dynamic_type")(fake_handler)

    scenario = _make_scenario("fake_dynamic_type", step_id="dyn1")
    WebRunner._entry_points_loaded = False

    with WebRunner(
        scenario=scenario,
        run_dir=run_dir,
        base_url="http://testserver",
        timeout=5,
    ) as runner:
        step = scenario.steps[0]
        result = runner.execute_step(step)

    assert result["success"] is True
    assert invoked.get("called") is True
    assert invoked.get("base_url") == "http://testserver"
    assert result.get("custom_key") == "custom_value"

    # Clean up so we don't pollute other tests.
    del registry._handlers["fake_dynamic_type"]


# ---------------------------------------------------------------------------
# Entry-points flag is idempotent within a single WebRunner lifecycle
# ---------------------------------------------------------------------------


def test_entry_points_loaded_flag_prevents_double_load(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """load_entry_points() must only be called once even if two runners are created."""
    import purpleforge.runners.plugins as plugins_mod

    call_count = 0
    original_load = registry.load_entry_points

    def counting_load(*args: Any, **kwargs: Any) -> int:
        nonlocal call_count
        call_count += 1
        return original_load(*args, **kwargs)

    monkeypatch.setattr(registry, "load_entry_points", counting_load)

    from purpleforge.runners.web import WebRunner

    # Force re-evaluation of the class-level flag.
    WebRunner._entry_points_loaded = False

    scenario = _make_scenario("http_get_baseline")

    with WebRunner(scenario=scenario, run_dir=run_dir, base_url="http://x", timeout=5):
        pass

    # Second instance — entry points must NOT be loaded again.
    run_dir2 = run_dir.parent / "run2"
    run_dir2.mkdir()
    (run_dir2 / "telemetry").mkdir()
    (run_dir2 / "ground_truth").mkdir()

    with WebRunner(scenario=scenario, run_dir=run_dir2, base_url="http://x", timeout=5):
        pass

    assert call_count == 1, (
        f"load_entry_points called {call_count} times; expected 1"
    )
