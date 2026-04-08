"""
Labelled dataset loader for the PurpleForge evaluation framework.

Loads YAML files that describe ground-truth labelled scenarios for
authorized defensive evaluation only. All referenced scenario files
are validated to exist at load time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, model_validator

from purpleforge.utils.exceptions import EvaluationError


class ExpectedDetection(BaseModel):
    """One expected detection entry within a dataset item."""

    step_id: str = Field(..., description="Step ID as defined in the scenario YAML.")
    should_detect: bool = Field(
        ...,
        description=(
            "True if this step should produce a detection above the tier-B threshold; "
            "False marks a deliberate negative (must NOT trigger)."
        ),
    )
    max_mttd_seconds: Optional[float] = Field(
        default=None,
        description="Maximum acceptable mean-time-to-detect in seconds (positive detections only).",
        ge=0,
    )

    model_config = {"frozen": True}


class DatasetItem(BaseModel):
    """One scenario/target pair with its labelled expected detections."""

    scenario: str = Field(..., description="Relative or absolute path to the scenario YAML file.")
    target: str = Field(..., description="Target URL for the scenario run.")
    expected_detections: List[ExpectedDetection] = Field(
        default_factory=list,
        description="Per-step ground-truth labels.",
    )
    att_ck_technique_map: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Optional explicit mapping of step_id -> ATT&CK technique string, "
            "overriding the scenario att_ck_techniques list for per-step stratification."
        ),
    )

    model_config = {"frozen": False}


class LabelledDataset(BaseModel):
    """
    Top-level model for a labelled evaluation dataset.

    Loaded from YAML; all referenced scenario files are checked for existence.
    For authorized defensive evaluation only.
    """

    name: str = Field(..., description="Dataset name.")
    description: str = Field(default="", description="Human-readable description.")
    correlation_window_seconds: int = Field(
        default=300,
        description="Correlation window passed to the runner (seconds).",
        gt=0,
    )
    items: List[DatasetItem] = Field(..., description="Dataset items.", min_length=1)

    # Resolved at validation time; not serialised.
    _resolved_base: Optional[Path] = None

    model_config = {"frozen": False}

    @model_validator(mode="after")
    def _check_step_ids_not_empty(self) -> "LabelledDataset":
        for item in self.items:
            for ed in item.expected_detections:
                if not ed.step_id.strip():
                    raise ValueError(
                        f"expected_detection in item '{item.scenario}' has an empty step_id."
                    )
        return self


def load_dataset(path: Path) -> LabelledDataset:
    """
    Load and validate a labelled dataset from *path*.

    Validates that all scenario files referenced in the dataset exist on disk
    (resolved relative to the dataset file's parent directory).

    Parameters
    ----------
    path:
        Path to the YAML dataset file.

    Returns
    -------
    LabelledDataset
        Validated dataset model.

    Raises
    ------
    EvaluationError
        If the file is missing, malformed, or references non-existent scenario files.
    """
    if not path.exists():
        raise EvaluationError(
            f"Dataset file not found: {path}",
            hint="Check that the path is correct and the file exists.",
        )

    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise EvaluationError(
            f"Failed to parse dataset YAML: {exc}",
            hint="Ensure the file is valid YAML syntax.",
        ) from exc

    if not isinstance(raw, dict):
        raise EvaluationError(
            "Dataset YAML must be a mapping at the top level.",
            hint="The file should start with keys like 'name:', 'items:', etc.",
        )

    try:
        dataset = LabelledDataset.model_validate(raw)
    except Exception as exc:
        raise EvaluationError(
            f"Dataset schema validation failed: {exc}",
            hint="Check the dataset YAML against the expected schema.",
        ) from exc

    base_dir = path.parent

    # Validate that every referenced scenario file exists.
    for item in dataset.items:
        scenario_path = Path(item.scenario)
        if not scenario_path.is_absolute():
            scenario_path = base_dir / scenario_path
        if not scenario_path.exists():
            raise EvaluationError(
                f"Scenario file not found: {scenario_path}",
                hint=(
                    f"Dataset item references '{item.scenario}'. "
                    "Check the path relative to the dataset file."
                ),
            )
        # Normalise to absolute so callers don't need the base dir.
        item.scenario = str(scenario_path.resolve())

    return dataset
