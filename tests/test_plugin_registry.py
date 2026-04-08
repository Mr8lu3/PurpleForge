"""Tests for the StepPluginRegistry in purpleforge.runners.plugins."""

import logging
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from purpleforge.runners.plugins import StepContext, StepPluginRegistry
from purpleforge.scenarios.models import ScenarioStep


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_step(step_type: str = "test_type") -> ScenarioStep:
    return ScenarioStep(
        id="s1",
        type=step_type,
        description="test step",
    )


def _make_ctx() -> StepContext:
    return StepContext(
        base_url="http://example.com",
        timeout=10,
        log_request=MagicMock(),
        logger=logging.getLogger("test"),
    )


def _noop_handler(
    step: ScenarioStep, result: Dict[str, Any], ctx: StepContext
) -> None:
    result["called"] = True


def _alt_handler(
    step: ScenarioStep, result: Dict[str, Any], ctx: StepContext
) -> None:
    result["called_alt"] = True


# ---------------------------------------------------------------------------
# register + get roundtrip
# ---------------------------------------------------------------------------


def test_register_and_get_roundtrip() -> None:
    reg = StepPluginRegistry()
    reg.register("my_type")(_noop_handler)

    handler = reg.get("my_type")
    assert handler is not None

    result: Dict[str, Any] = {}
    handler(_make_step("my_type"), result, _make_ctx())
    assert result.get("called") is True


def test_get_unknown_type_returns_none() -> None:
    reg = StepPluginRegistry()
    assert reg.get("nonexistent") is None


# ---------------------------------------------------------------------------
# Duplicate register overwrites with warning
# ---------------------------------------------------------------------------


def test_duplicate_register_overwrites_with_warning(caplog: pytest.LogCaptureFixture) -> None:
    reg = StepPluginRegistry()
    reg.register("dup_type")(_noop_handler)

    with caplog.at_level(logging.WARNING, logger="purpleforge.runners.plugins"):
        reg.register("dup_type")(_alt_handler)

    assert any("overwriting" in r.message for r in caplog.records)

    # The new handler should be active.
    result: Dict[str, Any] = {}
    handler = reg.get("dup_type")
    assert handler is not None
    handler(_make_step("dup_type"), result, _make_ctx())
    assert result.get("called_alt") is True
    assert "called" not in result


# ---------------------------------------------------------------------------
# all_types() returns sorted list
# ---------------------------------------------------------------------------


def test_all_types_sorted() -> None:
    reg = StepPluginRegistry()
    reg.register("zebra")(_noop_handler)
    reg.register("apple")(_noop_handler)
    reg.register("mango")(_noop_handler)

    assert reg.all_types() == ["apple", "mango", "zebra"]


def test_all_types_empty_registry() -> None:
    reg = StepPluginRegistry()
    assert reg.all_types() == []


# ---------------------------------------------------------------------------
# load_entry_points: good + bad entry points
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    """Minimal stand-in for importlib.metadata.EntryPoint."""

    def __init__(self, name: str, value: str, obj: Any, should_fail: bool = False) -> None:
        self.name = name
        self.value = value
        self._obj = obj
        self._should_fail = should_fail

    def load(self) -> Any:
        if self._should_fail:
            raise ImportError("simulated bad plugin")
        return self._obj


def test_load_entry_points_good_and_bad(caplog: pytest.LogCaptureFixture) -> None:
    reg = StepPluginRegistry()

    good_ep = _FakeEntryPoint("good_type", "some.module:handler", _noop_handler)
    bad_ep = _FakeEntryPoint("bad_type", "broken.module:handler", None, should_fail=True)

    with patch(
        "purpleforge.runners.plugins.importlib.metadata.entry_points",
        return_value=[good_ep, bad_ep],
    ):
        with caplog.at_level(logging.ERROR, logger="purpleforge.runners.plugins"):
            loaded = reg.load_entry_points(group="purpleforge.step_handlers")

    # One entry point successfully loaded.
    assert loaded == 1
    assert reg.get("good_type") is not None
    assert reg.get("bad_type") is None

    # Bad plugin error must be logged, not raised.
    assert any("bad_type" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Idempotent load (calling twice doesn't duplicate or re-import)
# ---------------------------------------------------------------------------


def test_load_entry_points_idempotent() -> None:
    reg = StepPluginRegistry()

    good_ep = _FakeEntryPoint("idempotent_type", "some.module:h", _noop_handler)
    call_count = 0

    def counting_load(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count
        call_count += 1
        return [good_ep]

    with patch(
        "purpleforge.runners.plugins.importlib.metadata.entry_points",
        side_effect=counting_load,
    ):
        reg.load_entry_points()
        reg.load_entry_points()  # second call — must be a no-op

    # importlib.metadata.entry_points should only have been consulted once.
    assert call_count == 1
    # Handler still present and not duplicated.
    assert reg.get("idempotent_type") is not None


def test_load_entry_points_idempotent_returns_zero_on_second_call() -> None:
    reg = StepPluginRegistry()

    with patch(
        "purpleforge.runners.plugins.importlib.metadata.entry_points",
        return_value=[],
    ):
        first = reg.load_entry_points()
        second = reg.load_entry_points()

    assert first == 0
    assert second == 0
