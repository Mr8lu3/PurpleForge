"""Tests for built-in step handlers and their registration."""

import logging
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from purpleforge.scenarios.models import ScenarioStep


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_step(step_type: str, **params: Any) -> ScenarioStep:
    return ScenarioStep(
        id="s1",
        type=step_type,
        description="test step",
        parameters=params,
        timeout_seconds=10,
    )


def _fake_ctx(log_request_mock: MagicMock) -> Any:
    """Return a StepContext with a mocked log_request."""
    from purpleforge.runners.plugins import StepContext

    return StepContext(
        base_url="http://testserver",
        timeout=10,
        log_request=log_request_mock,
        logger=logging.getLogger("test"),
    )


def _make_response(
    status_code: int = 200,
    text: str = "",
    url: str = "http://testserver/",
    headers: Dict[str, str] | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.url = url
    resp.content = text.encode()
    resp.headers = headers or {}
    return resp


# ---------------------------------------------------------------------------
# Registry contains all three built-in types after package import
# ---------------------------------------------------------------------------


def test_builtins_registered_on_import() -> None:
    """Importing purpleforge.runners must register the 3 built-in step types."""
    # The import of purpleforge.runners fires builtin_handlers side-effect.
    import purpleforge.runners  # noqa: F401
    from purpleforge.runners.plugins import registry

    registered = registry.all_types()
    assert "http_get_baseline" in registered
    assert "reflected_xss_probe_safe" in registered
    assert "sqli_error_probe_safe" in registered


# ---------------------------------------------------------------------------
# http_get_baseline handler
# ---------------------------------------------------------------------------


def test_http_get_baseline_mutates_result() -> None:
    from purpleforge.runners.builtin_handlers import handle_http_get_baseline

    log_request_mock = MagicMock()
    ctx = _fake_ctx(log_request_mock)
    step = _make_step("http_get_baseline", path="/healthz")
    result: Dict[str, Any] = {"evidence_collected": []}

    fake_resp = _make_response(status_code=200, text="ok", url="http://testserver/healthz")

    with patch("purpleforge.runners.builtin_handlers.requests.get", return_value=fake_resp):
        handle_http_get_baseline(step, result, ctx)

    assert result["status_code"] == 200
    assert "http_request_log" in result["evidence_collected"]
    # log_request called exactly once
    log_request_mock.assert_called_once()
    call_kwargs = log_request_mock.call_args.kwargs
    assert call_kwargs["method"] == "GET"
    assert call_kwargs["status_code"] == 200


# ---------------------------------------------------------------------------
# reflected_xss_probe_safe handler
# ---------------------------------------------------------------------------


def test_reflected_xss_probe_reflected_true() -> None:
    from purpleforge.runners.builtin_handlers import handle_reflected_xss_probe

    probe = "<test>"
    log_request_mock = MagicMock()
    ctx = _fake_ctx(log_request_mock)
    step = _make_step(
        "reflected_xss_probe_safe", path="/search", parameter="q", probe_string=probe
    )
    result: Dict[str, Any] = {"evidence_collected": []}

    # Response body contains the probe string — reflected.
    fake_resp = _make_response(
        status_code=200,
        text=f"You searched for: {probe}",
        url="http://testserver/search?q=%3Ctest%3E",
    )

    with patch("purpleforge.runners.builtin_handlers.requests.get", return_value=fake_resp):
        handle_reflected_xss_probe(step, result, ctx)

    assert result["reflected"] is True
    assert result["status_code"] == 200
    assert "http_request_log" in result["evidence_collected"]
    log_request_mock.assert_called_once()


def test_reflected_xss_probe_reflected_false() -> None:
    from purpleforge.runners.builtin_handlers import handle_reflected_xss_probe

    probe = "<test>"
    log_request_mock = MagicMock()
    ctx = _fake_ctx(log_request_mock)
    step = _make_step("reflected_xss_probe_safe", path="/", probe_string=probe)
    result: Dict[str, Any] = {"evidence_collected": []}

    fake_resp = _make_response(status_code=200, text="nothing here")

    with patch("purpleforge.runners.builtin_handlers.requests.get", return_value=fake_resp):
        handle_reflected_xss_probe(step, result, ctx)

    assert result["reflected"] is False


# ---------------------------------------------------------------------------
# sqli_error_probe_safe handler
# ---------------------------------------------------------------------------


def test_sqli_error_probe_detects_error() -> None:
    from purpleforge.runners.builtin_handlers import handle_sqli_error_probe

    log_request_mock = MagicMock()
    ctx = _fake_ctx(log_request_mock)
    step = _make_step("sqli_error_probe_safe", path="/items", parameter="id", probe_string="'")
    result: Dict[str, Any] = {"evidence_collected": []}

    fake_resp = _make_response(
        status_code=500,
        text="You have an error in your SQL syntax near '1'",
        url="http://testserver/items?id=%27",
    )

    with patch("purpleforge.runners.builtin_handlers.requests.get", return_value=fake_resp):
        handle_sqli_error_probe(step, result, ctx)

    assert result["error_detected"] is True
    assert result["status_code"] == 500
    assert "http_request_log" in result["evidence_collected"]
    log_request_mock.assert_called_once()


def test_sqli_error_probe_no_error() -> None:
    from purpleforge.runners.builtin_handlers import handle_sqli_error_probe

    log_request_mock = MagicMock()
    ctx = _fake_ctx(log_request_mock)
    step = _make_step("sqli_error_probe_safe")
    result: Dict[str, Any] = {"evidence_collected": []}

    fake_resp = _make_response(status_code=200, text="normal response")

    with patch("purpleforge.runners.builtin_handlers.requests.get", return_value=fake_resp):
        handle_sqli_error_probe(step, result, ctx)

    assert result["error_detected"] is False
