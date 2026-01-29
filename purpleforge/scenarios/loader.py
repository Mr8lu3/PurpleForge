"""Scenario loading and validation."""

import yaml
from pathlib import Path
from typing import Dict, List

from pydantic import ValidationError

from purpleforge.scenarios.models import Scenario
from purpleforge.utils.exceptions import ScenarioValidationError


def load_scenario(scenario_path: Path) -> Scenario:
    """
    Load and validate a scenario from a YAML file.

    Args:
        scenario_path: Path to scenario YAML file

    Returns:
        Validated Scenario object

    Raises:
        ScenarioValidationError: If scenario is invalid
    """
    if not scenario_path.exists():
        raise ScenarioValidationError(
            f"Scenario file not found: {scenario_path}",
            hint="Check the file path and try again",
        )

    try:
        with open(scenario_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ScenarioValidationError(
            f"Failed to parse YAML: {e}",
            hint="Check YAML syntax and formatting",
        )

    try:
        scenario = Scenario(**data)
        return scenario
    except ValidationError as e:
        raise ScenarioValidationError(
            f"Scenario validation failed:\n{format_validation_errors(e)}",
            hint="Review the scenario schema and fix validation errors",
        )


def validate_scenario(scenario_path: Path) -> tuple[bool, List[str], Scenario | None]:
    """
    Validate a scenario and return detailed results.

    Args:
        scenario_path: Path to scenario YAML file

    Returns:
        Tuple of (is_valid, error_messages, scenario_or_none)
    """
    try:
        scenario = load_scenario(scenario_path)
        return (True, [], scenario)
    except ScenarioValidationError as e:
        return (False, [e.message], None)


def format_validation_errors(error: ValidationError) -> str:
    """
    Format Pydantic validation errors into readable output.

    Args:
        error: Pydantic ValidationError

    Returns:
        Formatted error string
    """
    errors = []
    for err in error.errors():
        loc = " -> ".join(str(x) for x in err["loc"])
        msg = err["msg"]
        errors.append(f"  • {loc}: {msg}")
    return "\n".join(errors)
