"""Workspace and run directory management."""

import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from purpleforge import __version__
from purpleforge.utils.exceptions import WorkspaceError
from purpleforge.utils.logging import get_logger
from purpleforge.utils.platform import get_platform_info

logger = get_logger(__name__)


class RunStatus(str):
    """Run execution status."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class VerificationMetadata(BaseModel):
    """Target verification metadata."""

    status: str
    checked_at: datetime
    method: str

    model_config = {"frozen": False}


class RunMetadata(BaseModel):
    """Run metadata stored in meta.json."""

    run_id: str
    tool_version: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = Field(default=RunStatus.RUNNING)
    operator_acknowledgements: List[str] = Field(default_factory=list)
    target_verification: Optional[VerificationMetadata] = None
    scenario_hash: Optional[str] = None
    config_hash: Optional[str] = None
    platform: Dict[str, str] = Field(default_factory=dict)

    model_config = {"frozen": False}


class WorkspaceManager:
    """Manages workspace directories and run metadata."""

    def __init__(self, workspace_root: Path):
        """
        Initialize workspace manager.

        Args:
            workspace_root: Root directory for all runs
        """
        self.workspace_root = workspace_root.resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def create_run(
        self,
        scenario_name: str,
        acknowledgements: Optional[List[str]] = None,
    ) -> tuple[str, Path]:
        """
        Create a new run directory with metadata.

        Args:
            scenario_name: Name of scenario being executed
            acknowledgements: List of operator acknowledgements

        Returns:
            Tuple of (run_id, run_directory_path)

        Raises:
            WorkspaceError: If run directory creation fails
        """
        run_id = str(uuid.uuid4())
        run_dir = self.workspace_root / run_id

        try:
            # Create directory structure
            run_dir.mkdir(parents=True, exist_ok=False)
            (run_dir / "telemetry").mkdir()
            (run_dir / "telemetry" / "raw").mkdir()
            (run_dir / "artifacts").mkdir()
            (run_dir / "correlation").mkdir()
            (run_dir / "reports").mkdir()
            (run_dir / "ground_truth").mkdir()

            # Create initial metadata
            metadata = RunMetadata(
                run_id=run_id,
                tool_version=__version__,
                started_at=datetime.utcnow(),
                operator_acknowledgements=acknowledgements or [],
                platform=get_platform_info(),
            )

            self.save_metadata(run_dir, metadata)

            logger.info(f"Created run directory: {run_dir}")
            return run_id, run_dir

        except Exception as e:
            # Clean up on failure
            if run_dir.exists():
                shutil.rmtree(run_dir)
            raise WorkspaceError(
                f"Failed to create run directory: {e}",
                hint="Check workspace permissions and available disk space",
            )

    def save_metadata(self, run_dir: Path, metadata: RunMetadata) -> None:
        """
        Save run metadata to meta.json.

        Args:
            run_dir: Run directory path
            metadata: RunMetadata object to save
        """
        meta_path = run_dir / "meta.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata.model_dump(mode="json"), f, indent=2, default=str)

    def load_metadata(self, run_dir: Path) -> RunMetadata:
        """
        Load run metadata from meta.json.

        Args:
            run_dir: Run directory path

        Returns:
            RunMetadata object

        Raises:
            WorkspaceError: If metadata file is missing or invalid
        """
        meta_path = run_dir / "meta.json"
        if not meta_path.exists():
            raise WorkspaceError(
                f"Run metadata not found: {meta_path}",
                hint="This may not be a valid run directory",
            )

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return RunMetadata(**data)
        except Exception as e:
            raise WorkspaceError(
                f"Failed to load run metadata: {e}",
                hint="Metadata file may be corrupted",
            )

    def update_status(
        self,
        run_dir: Path,
        status: str,
        completed_at: Optional[datetime] = None,
    ) -> None:
        """
        Update run status in metadata.

        Args:
            run_dir: Run directory path
            status: New status value
            completed_at: Optional completion timestamp
        """
        metadata = self.load_metadata(run_dir)
        metadata.status = status
        if completed_at:
            metadata.completed_at = completed_at
        self.save_metadata(run_dir, metadata)

    def get_run_dir(self, run_id: str) -> Path:
        """
        Get run directory path for a run ID.

        Args:
            run_id: Run identifier

        Returns:
            Path to run directory

        Raises:
            WorkspaceError: If run directory doesn't exist
        """
        run_dir = self.workspace_root / run_id
        if not run_dir.exists():
            raise WorkspaceError(
                f"Run directory not found: {run_id}",
                hint="Check that the run ID is correct",
            )
        return run_dir

    def list_runs(self) -> List[tuple[str, RunMetadata]]:
        """
        List all runs in workspace.

        Returns:
            List of (run_id, metadata) tuples
        """
        runs = []
        for run_dir in self.workspace_root.iterdir():
            if run_dir.is_dir() and (run_dir / "meta.json").exists():
                try:
                    metadata = self.load_metadata(run_dir)
                    runs.append((run_dir.name, metadata))
                except Exception as e:
                    logger.warning(f"Failed to load metadata for {run_dir.name}: {e}")
        return sorted(runs, key=lambda x: x[1].started_at, reverse=True)
