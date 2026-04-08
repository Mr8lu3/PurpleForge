"""Example PurpleForge step handler plugin.

Demonstrates how a third party can add new step types without modifying the
core WebRunner. Operates on authorized targets only, for defensive assessment
purposes only.
"""

from typing import Any, Dict
from urllib.parse import urljoin

import requests

from purpleforge.runners.plugins import StepContext, register
from purpleforge.scenarios.models import ScenarioStep
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


@register("http_head_baseline")
def handle_http_head_baseline(
    step: ScenarioStep,
    result: Dict[str, Any],
    ctx: StepContext,
) -> None:
    """Perform a baseline HTTP HEAD request against an authorized target.

    HEAD requests retrieve only the response headers, not the body, making
    them lightweight fingerprinting probes. No payload injection. Safe.

    Parameters (``step.parameters``):
        path (str): URL path to request. Defaults to ``"/"``.
    """
    path: str = step.parameters.get("path", "/")
    url = urljoin(ctx.base_url, path)

    logger.info("HEAD %s", url)

    response = requests.head(
        url,
        timeout=step.timeout_seconds,
        allow_redirects=True,
        verify=True,
    )

    ctx.log_request(
        step_id=step.id,
        method="HEAD",
        url=url,
        status_code=response.status_code,
        response=response,
    )

    result["evidence_collected"].append("http_request_log")
    result["status_code"] = response.status_code
    result["server_header"] = response.headers.get("server", "")
    result["content_type"] = response.headers.get("content-type", "")
