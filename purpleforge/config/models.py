"""Pydantic models for configuration."""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class Config(BaseModel):
    """Main configuration for PurpleForge."""

    workspace_dir: Path = Field(default=Path("./runs"))
    scenarios_dir: Path = Field(default=Path("./scenarios"))
    log_level: str = Field(default="INFO")
    default_timeout: int = Field(default=30, gt=0, le=300)
    max_response_log_size: int = Field(default=200, gt=0, le=10000)

    @field_validator("workspace_dir", "scenarios_dir", mode="before")
    @classmethod
    def resolve_paths(cls, v: Path | str) -> Path:
        """Resolve paths to absolute paths."""
        path = Path(v)
        return path.resolve()

    model_config = {"frozen": False}


class TargetEntry(BaseModel):
    """Verified target entry in allowlist."""

    base_url: str
    verified_at: datetime
    token_hash: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    model_config = {"frozen": False}


class TargetAllowlist(BaseModel):
    """Container for verified targets."""

    targets: Dict[str, TargetEntry] = Field(default_factory=dict)

    model_config = {"frozen": False}
