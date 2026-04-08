"""
Tests for the 'purpleforge evaluate' CLI command.

All EvaluationRunner interactions are mocked; no live scenario execution occurs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from purpleforge.cli.main import app
from purpleforge.evaluation.dataset import LabelledDataset, DatasetItem, ExpectedDetection

runner = CliRunner(mix_stderr=False)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_CANNED_OBSERVATIONS: List[Dict[str, Any]] = [
    {
        "item_id": "web_baseline__http_localhost_8080",
        "step_id": "probe_xss",
        "should_detect": True,
        "detected": True,
        "confidence": 0.9,
        "tier": "A",
        "mttd_seconds": 15.0,
        "run_index": 0,
    },
    {
        "item_id": "web_baseline__http_localhost_8080",
        "step_id": "sqli_probe",
        "should_detect": False,
        "detected": False,
        "confidence": 0.1,
        "tier": "C",
        "mttd_seconds": None,
        "run_index": 0,
    },
]


@pytest.fixture()
def scenario_file(tmp_path: Path) -> Path:
    s = tmp_path / "scenarios" / "web_baseline.yml"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(
        "name: web_baseline\ndescription: test\ncategory: web\n"
        "target:\n  type: web\n  base_url: http://localhost\nsteps: []\n",
        encoding="utf-8",
    )
    return s


@pytest.fixture()
def dataset_file(tmp_path: Path, scenario_file: Path) -> Path:
    data = {
        "name": "cli_test_dataset",
        "description": "CLI test",
        "correlation_window_seconds": 300,
        "items": [
            {
                "scenario": str(scenario_file),
                "target": "http://localhost:8080",
                "expected_detections": [
                    {"step_id": "probe_xss", "should_detect": True},
                    {"step_id": "sqli_probe", "should_detect": False},
                ],
            }
        ],
    }
    p = tmp_path / "dataset.yml"
    p.write_text(yaml.dump(data), encoding="utf-8")
    return p


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    d = tmp_path / "eval_out"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _make_mock_dataset(dataset_file: Path) -> LabelledDataset:
    """Build a LabelledDataset that matches the fixture YAML (no file I/O required)."""
    item = DatasetItem(
        scenario=str(dataset_file.parent / "scenarios" / "web_baseline.yml"),
        target="http://localhost:8080",
        expected_detections=[
            ExpectedDetection(step_id="probe_xss", should_detect=True),
            ExpectedDetection(step_id="sqli_probe", should_detect=False),
        ],
    )
    return LabelledDataset(
        name="cli_test_dataset",
        description="CLI test",
        correlation_window_seconds=300,
        items=[item],
    )


class TestEvaluateCLI:
    def _invoke_with_mocks(
        self, dataset_file: Path, output_dir: Path
    ) -> Any:
        """Helper: invoke 'evaluate' with both load_dataset and EvaluationRunner mocked."""
        mock_dataset = _make_mock_dataset(dataset_file)
        with patch(
            "purpleforge.evaluation.runner.EvaluationRunner.execute",
            return_value=_CANNED_OBSERVATIONS,
        ), patch(
            "purpleforge.evaluation.dataset.load_dataset",
            return_value=mock_dataset,
        ):
            return runner.invoke(
                app,
                [
                    "evaluate",
                    str(dataset_file),
                    "--runs", "1",
                    "--output", str(output_dir),
                ],
            )

    def test_exit_zero_with_canned_observations(
        self, dataset_file: Path, output_dir: Path
    ) -> None:
        """CLI exits 0 when runner is mocked to return canned observations."""
        result = self._invoke_with_mocks(dataset_file, output_dir)
        assert result.exit_code == 0, result.output

    def test_metrics_files_written(
        self, dataset_file: Path, output_dir: Path
    ) -> None:
        """metrics.json, metrics.tex, and metrics.md are written to --output."""
        self._invoke_with_mocks(dataset_file, output_dir)
        assert (output_dir / "metrics.json").exists()
        assert (output_dir / "metrics.tex").exists()
        assert (output_dir / "metrics.md").exists()

    def test_console_contains_headline_metrics(
        self, dataset_file: Path, output_dir: Path
    ) -> None:
        """Console output must contain precision and recall labels."""
        result = self._invoke_with_mocks(dataset_file, output_dir)
        assert "Precision" in result.output
        assert "Recall" in result.output
        assert "F1" in result.output

    def test_dataset_not_found_nonzero_exit(self, tmp_path: Path) -> None:
        """Non-existent dataset file → non-zero exit, no Python traceback."""
        result = runner.invoke(
            app,
            [
                "evaluate",
                str(tmp_path / "ghost.yml"),
            ],
        )
        assert result.exit_code != 0
        assert "Traceback" not in result.output

    def test_dataset_not_found_no_traceback(self, tmp_path: Path) -> None:
        """Ensure no raw traceback is emitted on bad input."""
        result = runner.invoke(
            app,
            ["evaluate", str(tmp_path / "missing.yml")],
        )
        assert "Traceback" not in result.output
        assert "Traceback" not in (result.stderr or "")
