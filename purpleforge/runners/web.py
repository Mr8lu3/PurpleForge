"""Web scenario runner with safe assessment steps."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from purpleforge.audit.events import AuditEmitter
from purpleforge.audit.redaction import Redactor
from purpleforge.runners.plugins import StepContext, registry
from purpleforge.scenarios.models import Scenario, ScenarioStep
from purpleforge.utils.exceptions import RunnerError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class WebRunner:
    """Execute web assessment scenarios safely.

    Step dispatch is handled through the :class:`StepPluginRegistry`.  New step
    types can be added without modifying this class — register a handler with
    ``@purpleforge.runners.plugins.register("your_type")``.

    All operations must target authorized systems only, for defensive assessment
    purposes only.
    """

    # Class-level flag so entry points are discovered at most once per process.
    _entry_points_loaded: bool = False

    def __init__(
        self,
        scenario: Scenario,
        run_dir: Path,
        base_url: str,
        timeout: int = 30,
        max_response_log_size: int = 200,
        redaction_enabled: bool = True,
        audit_log_enabled: bool = True,
    ):
        """
        Initialize web runner.

        Args:
            scenario: Scenario to execute
            run_dir: Run directory for output
            base_url: Target base URL
            timeout: Default timeout for requests
            max_response_log_size: Max chars to log from response
            redaction_enabled: Whether to redact PII/secrets from telemetry
            audit_log_enabled: Whether to emit hash-chained audit events
        """
        # Ensure entry points are loaded once per process.
        if not WebRunner._entry_points_loaded:
            WebRunner._entry_points_loaded = True
            registry.load_entry_points()

        self.scenario = scenario
        self.run_dir = run_dir
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_response_log_size = max_response_log_size
        self._redactor = Redactor(enabled=redaction_enabled)
        self._audit: Optional[AuditEmitter] = (
            AuditEmitter(run_dir) if audit_log_enabled else None
        )

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
        if self._audit:
            self._audit.run_created(
                run_id=self.run_dir.name,
                scenario_name=self.scenario.name,
            )
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

        results: Dict[str, Any] = {
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

        if self._audit:
            self._audit.run_completed(
                status="completed",
                counts={
                    "total": results["total_steps"],
                    "successful": results["successful_steps"],
                    "failed": results["failed_steps"],
                },
            )

        return results

    def execute_step(self, step: ScenarioStep) -> Dict[str, Any]:
        """
        Execute a single scenario step via the plugin registry.

        Args:
            step: Step to execute

        Returns:
            Step result dictionary. On unknown step type the result has an
            ``error`` key and ``success=False`` but no exception is raised.
        """
        step_result: Dict[str, Any] = {
            "step_id": step.id,
            "step_type": step.type,
            "description": step.description,
            "timestamp": datetime.utcnow().isoformat(),
            "success": False,
            "evidence_collected": [],
        }

        if self._audit:
            self._audit.step_started(step.id)

        handler = registry.get(step.type)
        if handler is None:
            msg = (
                f"Unknown step type: {step.type}. "
                f"Registered: {registry.all_types()}"
            )
            step_result["error"] = msg
            logger.error(msg)
            # Write ground truth even for unknown types so the record is complete.
            self._write_ground_truth(step, step_result)
            if self._audit:
                self._audit.step_completed(step.id, "failed")
            return step_result

        ctx = StepContext(
            base_url=self.base_url,
            timeout=self.timeout,
            log_request=self._log_request,
            logger=logger,
        )

        try:
            handler(step, step_result, ctx)
            step_result["success"] = True
        except Exception as e:
            step_result["error"] = str(e)
            logger.error(f"Step handler error: {e}")

        # Write ground truth
        self._write_ground_truth(step, step_result)

        if self._audit:
            self._audit.step_completed(
                step.id, "success" if step_result["success"] else "failed"
            )

        return step_result

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
        log_entry: Dict[str, Any] = {
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

        log_entry = self._redactor.redact_dict(log_entry)
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
