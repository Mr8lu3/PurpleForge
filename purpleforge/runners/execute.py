"""
Programmatic scenario execution helper.

Provides a single entry point used by both the CLI ``run`` command and the
evaluation framework's :class:`~purpleforge.evaluation.runner.EvaluationRunner`.
This avoids duplicating runner logic between the two callers.

Authorised targets only. Defensive assessment use only.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from purpleforge.config import load_config
from purpleforge.correlation import CorrelationEngine
from purpleforge.runners import WebRunner
from purpleforge.scenarios import load_scenario
from purpleforge.scenarios.models import TargetType
from purpleforge.utils.exceptions import RunnerError
from purpleforge.utils.logging import get_logger
from purpleforge.workspace import WorkspaceManager
from purpleforge.workspace.manager import RunStatus

logger = get_logger(__name__)


def execute_scenario(
    scenario_path: Path,
    target: str,
    workspace_dir: Path,
    *,
    skip_prompts: bool = True,
) -> Path:
    """
    Execute a scenario programmatically and return the run directory.

    This function encapsulates the core execution logic shared between the
    ``purpleforge run`` CLI command and the evaluation runner. It does NOT
    perform ownership verification or controlled-mode prompts — callers are
    responsible for those checks before calling this function.

    Parameters
    ----------
    scenario_path:
        Absolute path to the scenario YAML file.
    target:
        Target base URL.
    workspace_dir:
        Workspace root directory; runs are created inside it.
    skip_prompts:
        When True (the default for programmatic use) interactive prompts are
        suppressed. Has no effect at present but is reserved for future use.

    Returns
    -------
    Path
        The ``run_dir`` that was created and populated.

    Raises
    ------
    RunnerError
        On execution failure.
    """
    try:
        config = load_config()

        scenario = load_scenario(scenario_path)
        logger.info("Loaded scenario '%s' from %s", scenario.name, scenario_path)

        workspace_manager = WorkspaceManager(workspace_dir)
        run_id, run_dir = workspace_manager.create_run(
            scenario_name=scenario.name,
            acknowledgements=[],
        )
        logger.info("Created run %s at %s", run_id, run_dir)

        # Copy scenario into run directory.
        shutil.copy(scenario_path, run_dir / "scenario.yaml")

        # Save target metadata.
        target_metadata = {
            "base_url": target,
            "verification_status": "skipped",
            "verified_at": datetime.utcnow().isoformat(),
        }
        (run_dir / "target.json").write_text(
            json.dumps(target_metadata, indent=2), encoding="utf-8"
        )

        # Record scenario hash.
        metadata = workspace_manager.load_metadata(run_dir)
        metadata.scenario_hash = hashlib.sha256(
            scenario_path.read_bytes()
        ).hexdigest()
        workspace_manager.save_metadata(run_dir, metadata)

        # Execute scenario steps.
        if scenario.target.type == TargetType.WEB:
            with WebRunner(
                scenario=scenario,
                run_dir=run_dir,
                base_url=target,
                timeout=config.default_timeout,
                max_response_log_size=config.max_response_log_size,
            ) as runner:
                runner.execute()
        else:
            raise RunnerError(
                f"Unsupported target type for programmatic execution: {scenario.target.type}",
                hint="Only web scenarios are currently supported by execute_scenario.",
            )

        # Run correlation so coverage.json and timeline.json are produced.
        correlation_engine = CorrelationEngine(run_dir)
        correlation_engine.correlate()

        workspace_manager.update_status(
            run_dir,
            RunStatus.COMPLETED,
            completed_at=datetime.utcnow(),
        )

        logger.info("Scenario execution complete for run %s", run_id)
        return run_dir

    except RunnerError:
        raise
    except Exception as exc:
        raise RunnerError(
            f"Scenario execution failed: {exc}",
            hint="Check logs for details.",
        ) from exc
