"""Tests for report generation."""

import pytest
from pathlib import Path
import tempfile
import shutil
import json

from purpleforge.workspace.manager import WorkspaceManager
from purpleforge.reporting.generator import ReportGenerator


@pytest.fixture
def temp_workspace():
    """Create temporary workspace directory."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir)


def test_report_generation(temp_workspace):
    """Test basic report generation."""
    # Create run directory
    manager = WorkspaceManager(temp_workspace)
    run_id, run_dir = manager.create_run("Test Scenario")

    # Create minimal data files
    (run_dir / "scenario.yaml").write_text(
        """
name: Test Scenario
description: Test description
category: web
target:
  type: web
  base_url: http://example.com
steps: []
"""
    )

    (run_dir / "target.json").write_text(
        json.dumps({"base_url": "http://example.com"})
    )

    (run_dir / "correlation" / "coverage.json").write_text(
        json.dumps(
            {
                "total_steps": 0,
                "steps_with_evidence": 0,
                "coverage_percentage": 0.0,
                "step_coverage": [],
            }
        )
    )

    (run_dir / "correlation" / "timeline.json").write_text(json.dumps([]))

    # Generate report
    generator = ReportGenerator(run_dir)
    report_path = generator.generate()

    assert report_path.exists()
    assert report_path.suffix == ".md"

    # Check report contains expected sections
    content = report_path.read_text()
    assert "PurpleForge Incident Report" in content
    assert run_id in content
