"""Tests for workspace management."""

import pytest
from pathlib import Path
import tempfile
import shutil

from purpleforge.workspace.manager import WorkspaceManager, RunMetadata


@pytest.fixture
def temp_workspace():
    """Create temporary workspace directory."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir)


def test_create_run(temp_workspace):
    """Test run directory creation."""
    manager = WorkspaceManager(temp_workspace)

    run_id, run_dir = manager.create_run("Test Scenario")

    assert run_dir.exists()
    assert (run_dir / "meta.json").exists()
    assert (run_dir / "telemetry").exists()
    assert (run_dir / "artifacts").exists()
    assert (run_dir / "correlation").exists()
    assert (run_dir / "reports").exists()
    assert (run_dir / "ground_truth").exists()


def test_load_metadata(temp_workspace):
    """Test metadata loading."""
    manager = WorkspaceManager(temp_workspace)

    run_id, run_dir = manager.create_run("Test Scenario")

    metadata = manager.load_metadata(run_dir)

    assert metadata.run_id == run_id
    assert metadata.status == "running"


def test_update_status(temp_workspace):
    """Test status update."""
    manager = WorkspaceManager(temp_workspace)

    run_id, run_dir = manager.create_run("Test Scenario")

    manager.update_status(run_dir, "completed")

    metadata = manager.load_metadata(run_dir)
    assert metadata.status == "completed"


def test_list_runs(temp_workspace):
    """Test listing runs."""
    manager = WorkspaceManager(temp_workspace)

    # Create multiple runs
    manager.create_run("Scenario 1")
    manager.create_run("Scenario 2")
    manager.create_run("Scenario 3")

    runs = manager.list_runs()

    assert len(runs) == 3
