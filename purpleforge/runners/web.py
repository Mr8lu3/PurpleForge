"""Web scenario runner with safe assessment steps."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, quote

import requests

from purpleforge.scenarios.models import Scenario, ScenarioStep
from purpleforge.utils.exceptions import RunnerError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class WebRunner:
    """Execute web assessment scenarios safely."""

    def __init__(
        self,
        scenario: Scenario,
        run_dir: Path,
        base_url: str,
        timeout: int = 30,
        max_response_log_size: int = 200,
    ):
        """
        Initialize web runner.

        Args:
            scenario: Scenario to execute
            run_dir: Run directory for output
            base_url: Target base URL
            timeout: Default timeout for requests
            max_response_log_size: Max chars to log from response
        """
        self.scenario = scenario
        self.run_dir = run_dir
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_response_log_size = max_response_log_size

        self.telemetry_dir = run_dir / "telemetry"
        self.ground_truth_dir = run_dir / "ground_truth"

        # Open log files
        self.web_requests_log = open(
            self.telemetry_dir / "web_requests.jsonl", "w", encoding="utf-8"
        )
        self.ground_truth_log = open(
            self.ground_truth_dir / "expected_evidence.jsonl", "w", encoding="utf-8"
        )

    def __enter__(self) -> "WebRunner":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit - close log files."""
        self.web_requests_log.close()
        self.ground_truth_log.close()

    def execute(self) -> Dict[str, Any]:
        """
        Execute all steps in the scenario.

        Returns:
            Execution summary with step results

        Raises:
            RunnerError: If execution fails critically
        """
        logger.info(f"Starting web scenario: {self.scenario.name}")

        results = {
            "scenario_name": self.scenario.name,
            "started_at": datetime.utcnow().isoformat(),
            "steps": [],
            "total_steps": len(self.scenario.steps),
            "successful_steps": 0,
            "failed_steps": 0,
        }

        for step in self.scenario.steps:
            logger.info(f"Executing step: {step.id} - {step.description}")

            try:
                step_result = self.execute_step(step)
                results["steps"].append(step_result)

                if step_result["success"]:
                    results["successful_steps"] += 1
                else:
                    results["failed_steps"] += 1

                    if not step.continue_on_failure:
                        logger.warning(f"Step failed and continue_on_failure=False, stopping")
                        break

            except Exception as e:
                logger.error(f"Step {step.id} raised exception: {e}")
                results["steps"].append(
                    {
                        "step_id": step.id,
                        "success": False,
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
                results["failed_steps"] += 1

                if not step.continue_on_failure:
                    break

        results["completed_at"] = datetime.utcnow().isoformat()

        logger.info(
            f"Scenario complete: {results['successful_steps']}/{results['total_steps']} steps successful"
        )

        return results

    def execute_step(self, step: ScenarioStep) -> Dict[str, Any]:
        """
        Execute a single scenario step.

        Args:
            step: Step to execute

        Returns:
            Step result dictionary
        """
        step_result = {
            "step_id": step.id,
            "step_type": step.type,
            "description": step.description,
            "timestamp": datetime.utcnow().isoformat(),
            "success": False,
            "evidence_collected": [],
        }

        # Dispatch to appropriate handler
        handlers = {
            "http_get_baseline": self._handle_http_get_baseline,
            "reflected_xss_probe_safe": self._handle_reflected_xss_probe,
            "sqli_error_probe_safe": self._handle_sqli_error_probe,
        }

        handler = handlers.get(step.type)
        if not handler:
            step_result["error"] = f"Unknown step type: {step.type}"
            logger.error(step_result["error"])
            return step_result

        try:
            handler(step, step_result)
            step_result["success"] = True
        except Exception as e:
            step_result["error"] = str(e)
            logger.error(f"Step handler error: {e}")

        # Write ground truth
        self._write_ground_truth(step, step_result)

        return step_result

    def _handle_http_get_baseline(
        self, step: ScenarioStep, result: Dict[str, Any]
    ) -> None:
        """
        Handle HTTP GET baseline request.

        Parameters:
            - path: URL path to request (default: "/")
        """
        path = step.parameters.get("path", "/")
        url = urljoin(self.base_url, path)

        logger.info(f"GET {url}")

        response = requests.get(
            url,
            timeout=step.timeout_seconds,
            allow_redirects=True,
            verify=True,
        )

        self._log_request(
            step_id=step.id,
            method="GET",
            url=url,
            status_code=response.status_code,
            response=response,
        )

        result["evidence_collected"].append("http_request_log")
        result["status_code"] = response.status_code

    def _handle_reflected_xss_probe(
        self, step: ScenarioStep, result: Dict[str, Any]
    ) -> None:
        """
        Handle safe reflected XSS probe.

        Checks if input is reflected in response without executing scripts.

        Parameters:
            - path: URL path to test
            - parameter: Query parameter name
            - probe_string: Safe probe string (default: "<test>")
        """
        path = step.parameters.get("path", "/")
        param_name = step.parameters.get("parameter", "q")
        probe = step.parameters.get("probe_string", "<test>")

        url = urljoin(self.base_url, path)
        params = {param_name: probe}

        logger.info(f"XSS probe: GET {url}?{param_name}={probe}")

        response = requests.get(
            url,
            params=params,
            timeout=step.timeout_seconds,
            allow_redirects=True,
            verify=True,
        )

        self._log_request(
            step_id=step.id,
            method="GET",
            url=response.url,
            status_code=response.status_code,
            response=response,
            probe_info={"type": "xss_reflection", "probe": probe},
        )

        # Check for reflection
        reflected = probe in response.text
        result["evidence_collected"].append("http_request_log")
        result["reflected"] = reflected
        result["status_code"] = response.status_code

        if reflected:
            logger.info("Probe string reflected in response")
        else:
            logger.info("Probe string not reflected")

    def _handle_sqli_error_probe(
        self, step: ScenarioStep, result: Dict[str, Any]
    ) -> None:
        """
        Handle safe SQL injection error probe.

        Checks for SQL error messages without data extraction.

        Parameters:
            - path: URL path to test
            - parameter: Query parameter name
            - probe_string: Safe probe string (default: "'")
        """
        path = step.parameters.get("path", "/")
        param_name = step.parameters.get("parameter", "id")
        probe = step.parameters.get("probe_string", "'")

        url = urljoin(self.base_url, path)
        params = {param_name: probe}

        logger.info(f"SQLi probe: GET {url}?{param_name}={probe}")

        response = requests.get(
            url,
            params=params,
            timeout=step.timeout_seconds,
            allow_redirects=True,
            verify=True,
        )

        self._log_request(
            step_id=step.id,
            method="GET",
            url=response.url,
            status_code=response.status_code,
            response=response,
            probe_info={"type": "sqli_error", "probe": probe},
        )

        # Check for common SQL error patterns
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
        error_detected = any(pattern in response_lower for pattern in error_patterns)

        result["evidence_collected"].append("http_request_log")
        result["error_detected"] = error_detected
        result["status_code"] = response.status_code

        if error_detected:
            logger.info("SQL error pattern detected in response")
        else:
            logger.info("No SQL error pattern detected")

    def _log_request(
        self,
        step_id: str,
        method: str,
        url: str,
        status_code: int,
        response: requests.Response,
        probe_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log HTTP request to telemetry.

        Args:
            step_id: Step identifier
            method: HTTP method
            url: Request URL
            status_code: Response status code
            response: Response object
            probe_info: Optional probe metadata
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "step_id": step_id,
            "method": method,
            "url": url,
            "status_code": status_code,
            "response_length": len(response.content),
            "headers": {
                "content-type": response.headers.get("content-type"),
                "server": response.headers.get("server"),
                "content-length": response.headers.get("content-length"),
            },
            "response_snippet": response.text[: self.max_response_log_size],
        }

        if probe_info:
            log_entry["probe_info"] = probe_info

        self.web_requests_log.write(json.dumps(log_entry) + "\n")
        self.web_requests_log.flush()

    def _write_ground_truth(
        self, step: ScenarioStep, result: Dict[str, Any]
    ) -> None:
        """
        Write ground truth entry for correlation.

        Args:
            step: Step that was executed
            result: Step execution result
        """
        ground_truth_entry = {
            "timestamp": result["timestamp"],
            "step_id": step.id,
            "step_type": step.type,
            "expected_evidence": step.expected_evidence,
            "evidence_collected": result.get("evidence_collected", []),
            "success": result["success"],
        }

        self.ground_truth_log.write(json.dumps(ground_truth_entry) + "\n")
        self.ground_truth_log.flush()
