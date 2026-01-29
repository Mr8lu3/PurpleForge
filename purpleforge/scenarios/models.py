"""Pydantic models for scenario schema."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ScenarioCategory(str, Enum):
    """Scenario category."""

    WEB = "web"
    NETWORK = "network"
    BINARY = "binary"
    COMPOSITE = "composite"


class ScenarioMode(str, Enum):
    """Scenario execution mode."""

    ASSESS = "assess"
    CONTROLLED = "controlled"


class TargetType(str, Enum):
    """Target type."""

    WEB = "web"
    BINARY = "binary"
    NETWORK = "network"


class Target(BaseModel):
    """Target specification."""

    base_url: Optional[str] = None
    type: TargetType
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: Optional[str], info: Any) -> Optional[str]:
        """Validate that web targets have a base_url."""
        if info.data.get("type") == TargetType.WEB and not v:
            raise ValueError("base_url is required for web targets")
        return v

    model_config = {"frozen": False}


class ScenarioStep(BaseModel):
    """Individual step in a scenario."""

    id: str
    type: str
    description: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    expected_evidence: List[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=30, gt=0, le=300)
    continue_on_failure: bool = Field(default=False)

    model_config = {"frozen": False}


class Scenario(BaseModel):
    """Complete scenario definition."""

    name: str
    description: str
    category: ScenarioCategory
    mode: ScenarioMode = Field(default=ScenarioMode.ASSESS)
    ownership_verification: bool = Field(default=True)
    target: Target
    steps: List[ScenarioStep]
    att_ck_techniques: List[str] = Field(default_factory=list)

    @field_validator("steps")
    @classmethod
    def validate_unique_step_ids(cls, v: List[ScenarioStep]) -> List[ScenarioStep]:
        """Ensure step IDs are unique."""
        ids = [step.id for step in v]
        if len(ids) != len(set(ids)):
            raise ValueError("Step IDs must be unique within a scenario")
        return v

    @field_validator("ownership_verification")
    @classmethod
    def validate_ownership_verification(cls, v: bool, info: Any) -> bool:
        """Web scenarios should have ownership verification by default."""
        if info.data.get("target") and info.data["target"].type == TargetType.WEB:
            if not v:
                # Allow explicit false, but warn in validation output
                pass
        return v

    model_config = {"frozen": False}
