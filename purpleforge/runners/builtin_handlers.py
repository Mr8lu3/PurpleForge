"""Built-in step handlers for PurpleForge web assessment scenarios.

All handlers operate on authorized targets only. They implement safe,
non-exploiting detection probes for defensive security assessment purposes.
No exploitation, data exfiltration, or destructive behaviour is permitted.

Importing this module registers the three built-in handlers with the
module-level registry singleton via the ``@register`` decorator.
"""

from typing import Any, Dict
from urllib.parse import urljoin

import requests

from purpleforge.runners.plugins import StepContext, register
from purpleforge.scenarios.models import ScenarioStep
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


@register("http_get_baseline")
def handle_http_get_baseline(
    step: ScenarioStep,
    result: Dict[str, Any],
    ctx: StepContext,
) -> None:
    """Perform a baseline HTTP GET request against an authorized target.

    Records the response status code and logs the full request to telemetry.
    Safe: read-only, no payload injection.

    Parameters (``step.parameters``):
        path (str): URL path to request. Defaults to ``"/"``.
    """
    path: str = step.parameters.get("path", "/")
    url = urljoin(ctx.base_url, path)

    logger.info("GET %s", url)

    response = requests.get(
        url,
        timeout=step.timeout_seconds,
        allow_redirects=True,
        verify=True,
    )

    ctx.log_request(
        step_id=step.id,
        method="GET",
        url=url,
        status_code=response.status_code,
        response=response,
    )

    result["evidence_collected"].append("http_request_log")
    result["status_code"] = response.status_code


@register("reflected_xss_probe_safe")
def handle_reflected_xss_probe(
    step: ScenarioStep,
    result: Dict[str, Any],
    ctx: StepContext,
) -> None:
    """Check whether a benign probe string is reflected in the HTTP response.

    This is a *safe* reflected-XSS indicator check: it detects reflection of
    a non-executable string without injecting or executing scripts. Operates on
    authorized targets only.

    Parameters (``step.parameters``):
        path (str): URL path to test. Defaults to ``"/"``.
        parameter (str): Query parameter name. Defaults to ``"q"``.
        probe_string (str): Safe probe value. Defaults to ``"<test>"``.
    """
    path: str = step.parameters.get("path", "/")
    param_name: str = step.parameters.get("parameter", "q")
    probe: str = step.parameters.get("probe_string", "<test>")

    url = urljoin(ctx.base_url, path)
    params = {param_name: probe}

    logger.info("XSS probe: GET %s?%s=%s", url, param_name, probe)

    response = requests.get(
        url,
        params=params,
        timeout=step.timeout_seconds,
        allow_redirects=True,
        verify=True,
    )

    ctx.log_request(
        step_id=step.id,
        method="GET",
        url=response.url,
        status_code=response.status_code,
        response=response,
        probe_info={"type": "xss_reflection", "probe": probe},
    )

    reflected: bool = probe in response.text
    result["evidence_collected"].append("http_request_log")
    result["reflected"] = reflected
    result["status_code"] = response.status_code

    if reflected:
        logger.info("Probe string reflected in response")
    else:
        logger.info("Probe string not reflected")


@register("sqli_error_probe_safe")
def handle_sqli_error_probe(
    step: ScenarioStep,
    result: Dict[str, Any],
    ctx: StepContext,
) -> None:
    """Check for SQL error message leakage in the HTTP response.

    This is a *safe* SQL-injection indicator check: it detects whether the
    server leaks database error messages in response to a minimal quote
    character. No data extraction, no blind techniques. Operates on authorized
    targets only.

    Parameters (``step.parameters``):
        path (str): URL path to test. Defaults to ``"/"``.
        parameter (str): Query parameter name. Defaults to ``"id"``.
        probe_string (str): Safe probe value. Defaults to ``"'"``.
    """
    path: str = step.parameters.get("path", "/")
    param_name: str = step.parameters.get("parameter", "id")
    probe: str = step.parameters.get("probe_string", "'")

    url = urljoin(ctx.base_url, path)
    params = {param_name: probe}

    logger.info("SQLi probe: GET %s?%s=%s", url, param_name, probe)

    response = requests.get(
        url,
        params=params,
        timeout=step.timeout_seconds,
        allow_redirects=True,
        verify=True,
    )

    ctx.log_request(
        step_id=step.id,
        method="GET",
        url=response.url,
        status_code=response.status_code,
        response=response,
        probe_info={"type": "sqli_error", "probe": probe},
    )

    error_patterns = [
        "sql syntax",
        "mysql_fetch",
        "pg_query",
        "sqlite_query",
        "odbc_exec",
        "syntax error",
        "unterminated string",
    ]

    response_lower = response.text.lower()
    error_detected: bool = any(pattern in response_lower for pattern in error_patterns)

    result["evidence_collected"].append("http_request_log")
    result["error_detected"] = error_detected
    result["status_code"] = response.status_code

    if error_detected:
        logger.info("SQL error pattern detected in response")
    else:
        logger.info("No SQL error pattern detected")
