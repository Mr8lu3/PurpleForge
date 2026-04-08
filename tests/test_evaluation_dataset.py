"""
Tests for purpleforge.evaluation.dataset.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from purpleforge.evaluation.dataset import load_dataset, LabelledDataset
from purpleforge.utils.exceptions import EvaluationError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def scenario_file(tmp_path: Path) -> Path:
    """Create a minimal dummy scenario YAML so the loader's path check passes."""
    s = tmp_path / "scenarios" / "web_baseline.yml"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(
        "name: test\ndescription: test\ncategory: web\ntarget:\n  type: web\n  base_url: http://localhost\nsteps: []\n",
        encoding="utf-8",
    )
    return s


@pytest.fixture()
def valid_dataset_yaml(tmp_path: Path, scenario_file: Path) -> Path:
    """Write a valid dataset YAML that references the dummy scenario."""
    data = {
        "name": "test_dataset",
        "description": "A test dataset",
        "correlation_window_seconds": 300,
        "items": [
            {
                "scenario": str(scenario_file),
                "target": "http://localhost:8080",
                "expected_detections": [
                    {"step_id": "probe_xss", "should_detect": True, "max_mttd_seconds": 60},
                    {"step_id": "sqli_probe", "should_detect": False},
                ],
            }
        ],
    }
    p = tmp_path / "dataset.yml"
    p.write_text(yaml.dump(data), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLoadDataset:
    def test_valid_yaml_loads(self, valid_dataset_yaml: Path) -> None:
        ds = load_dataset(valid_dataset_yaml)
        assert isinstance(ds, LabelledDataset)
        assert ds.name == "test_dataset"
        assert len(ds.items) == 1
        assert len(ds.items[0].expected_detections) == 2

    def test_expected_detections_parsed(self, valid_dataset_yaml: Path) -> None:
        ds = load_dataset(valid_dataset_yaml)
        ed = ds.items[0].expected_detections
        assert ed[0].step_id == "probe_xss"
        assert ed[0].should_detect is True
        assert ed[0].max_mttd_seconds == pytest.approx(60.0)
        assert ed[1].step_id == "sqli_probe"
        assert ed[1].should_detect is False

    def test_missing_dataset_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(EvaluationError, match="Dataset file not found"):
            load_dataset(tmp_path / "nonexistent.yml")

    def test_missing_scenario_file_raises(self, tmp_path: Path) -> None:
        data = {
            "name": "broken",
            "items": [
                {
                    "scenario": "does_not_exist.yml",
                    "target": "http://localhost",
                    "expected_detections": [{"step_id": "s1", "should_detect": True}],
                }
            ],
        }
        p = tmp_path / "dataset.yml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        with pytest.raises(EvaluationError, match="Scenario file not found"):
            load_dataset(p)

    def test_missing_scenario_file_hint_present(self, tmp_path: Path) -> None:
        data = {
            "name": "broken",
            "items": [
                {
                    "scenario": "ghost.yml",
                    "target": "http://localhost",
                    "expected_detections": [{"step_id": "s1", "should_detect": True}],
                }
            ],
        }
        p = tmp_path / "dataset.yml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        try:
            load_dataset(p)
        except EvaluationError as exc:
            assert exc.hint is not None
            assert "ghost.yml" in exc.hint
        else:
            pytest.fail("EvaluationError was not raised")

    def test_invalid_schema_raises(self, tmp_path: Path) -> None:
        # 'items' is required; omitting it causes validation error.
        data = {"name": "no_items"}
        p = tmp_path / "dataset.yml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        with pytest.raises(EvaluationError, match="(schema validation|validation)"):
            load_dataset(p)

    def test_invalid_yaml_syntax_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yml"
        p.write_text("name: [unclosed", encoding="utf-8")
        with pytest.raises(EvaluationError, match="(parse|YAML|syntax)"):
            load_dataset(p)

    def test_scenario_path_resolved_to_absolute(
        self, valid_dataset_yaml: Path, scenario_file: Path
    ) -> None:
        ds = load_dataset(valid_dataset_yaml)
        assert Path(ds.items[0].scenario).is_absolute()

    def test_empty_step_id_raises(self, tmp_path: Path, scenario_file: Path) -> None:
        data = {
            "name": "bad_step_id",
            "items": [
                {
                    "scenario": str(scenario_file),
                    "target": "http://localhost",
                    "expected_detections": [{"step_id": "   ", "should_detect": True}],
                }
            ],
        }
        p = tmp_path / "dataset.yml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        with pytest.raises(EvaluationError):
            load_dataset(p)
