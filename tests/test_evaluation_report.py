"""
Tests for purpleforge.evaluation.report.EvaluationReport.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from purpleforge.evaluation.dataset import LabelledDataset, DatasetItem, ExpectedDetection
from purpleforge.evaluation.report import EvaluationReport

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------


def _make_dataset() -> LabelledDataset:
    item = DatasetItem(
        scenario="/fake/scenario.yml",
        target="http://localhost:8080",
        expected_detections=[
            ExpectedDetection(step_id="probe_xss", should_detect=True),
            ExpectedDetection(step_id="sqli_probe", should_detect=False),
        ],
    )
    return LabelledDataset(
        name="report_test_dataset",
        description="Unit test dataset",
        correlation_window_seconds=300,
        items=[item],
    )


def _make_observations() -> List[Dict[str, Any]]:
    return [
        {
            "item_id": "item1",
            "step_id": "probe_xss",
            "should_detect": True,
            "detected": True,
            "confidence": 0.9,
            "tier": "A",
            "mttd_seconds": 20.0,
            "run_index": 0,
        },
        {
            "item_id": "item1",
            "step_id": "sqli_probe",
            "should_detect": False,
            "detected": False,
            "confidence": 0.1,
            "tier": "C",
            "mttd_seconds": None,
            "run_index": 0,
        },
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestComputeAll:
    def test_returns_expected_keys(self) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        result = report.compute_all()
        assert "overall" in result
        assert "mttd" in result
        assert "reproducibility" in result
        assert "false_positive_rate" in result
        assert "per_technique" in result
        assert "dataset_meta" in result

    def test_dataset_meta_populated(self) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        meta = report.compute_all()["dataset_meta"]
        assert meta["name"] == "report_test_dataset"
        assert meta["n_items"] == 1
        assert meta["n_observations"] == 2

    def test_overall_values_correct(self) -> None:
        # TP=1 (probe_xss), TN=1 (sqli_probe) → precision=1, recall=1, F1=1
        report = EvaluationReport(_make_observations(), _make_dataset())
        overall = report.compute_all()["overall"]
        assert overall["precision"] == pytest.approx(1.0)
        assert overall["recall"] == pytest.approx(1.0)
        assert overall["f1"] == pytest.approx(1.0)

    def test_compute_all_cached(self) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        r1 = report.compute_all()
        r2 = report.compute_all()
        assert r1 is r2  # same object → cache hit


class TestToJson:
    def test_file_created(self, tmp_path: Path) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.json"
        report.to_json(path)
        assert path.exists()

    def test_roundtrip(self, tmp_path: Path) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.json"
        report.to_json(path)
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded["overall"]["precision"] == pytest.approx(1.0)
        assert loaded["dataset_meta"]["name"] == "report_test_dataset"

    def test_sorted_keys(self, tmp_path: Path) -> None:
        """JSON must have sorted keys for deterministic output."""
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.json"
        report.to_json(path)
        raw = path.read_text(encoding="utf-8")
        # Verify it is valid JSON.
        json.loads(raw)
        # Check "dataset_meta" appears before "mttd" (alphabetical).
        assert raw.index('"dataset_meta"') < raw.index('"mttd"')


class TestToLatexTable:
    def test_file_created(self, tmp_path: Path) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.tex"
        report.to_latex_table(path)
        assert path.exists()

    def test_contains_tabular(self, tmp_path: Path) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.tex"
        report.to_latex_table(path)
        content = path.read_text(encoding="utf-8")
        assert r"\begin{tabular}" in content
        assert r"\end{tabular}" in content

    def test_has_phase5_comment(self, tmp_path: Path) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.tex"
        report.to_latex_table(path)
        content = path.read_text(encoding="utf-8")
        assert "Generated by PurpleForge Phase 5" in content

    def test_no_unescaped_percent_in_numbers(self, tmp_path: Path) -> None:
        """
        Float metric values must not contain a bare '%' character.

        The LaTeX escape function replaces '%' with '\\%'. Since our metric
        values are plain floats formatted as decimal strings, they will never
        naturally contain '%'. This test confirms neither the values nor any
        accidental formatting artefacts introduce a bare '%'.
        """
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.tex"
        report.to_latex_table(path)
        content = path.read_text(encoding="utf-8")
        # A bare '%' not preceded by backslash is a LaTeX comment — unsafe.
        import re
        bare_percent = re.compile(r"(?<!\\)%")
        # The comment line starts with "% Generated…" which is allowed (it IS a comment)
        # but that is the only '%' in the file and it's intentional.
        # We allow the comment line at the top.
        lines = content.splitlines()
        for line in lines:
            if line.startswith("%"):
                continue  # top-level LaTeX comment line — intentional
            assert not bare_percent.search(line), (
                f"Bare '%' found in non-comment LaTeX line: {line!r}"
            )

    def test_no_documentclass(self, tmp_path: Path) -> None:
        """Fragment must not contain \\documentclass."""
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.tex"
        report.to_latex_table(path)
        assert r"\documentclass" not in path.read_text(encoding="utf-8")


class TestToMarkdown:
    def test_file_created(self, tmp_path: Path) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.md"
        report.to_markdown(path)
        assert path.exists()

    def test_contains_expected_keywords(self, tmp_path: Path) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.md"
        report.to_markdown(path)
        content = path.read_text(encoding="utf-8")
        assert "Precision" in content
        assert "Recall" in content
        assert "F1" in content
        assert "MTTD" in content
        assert "Reproducibility" in content
        assert "False Positive Rate" in content
        assert "Confusion Matrix" in content

    def test_dataset_name_in_heading(self, tmp_path: Path) -> None:
        report = EvaluationReport(_make_observations(), _make_dataset())
        path = tmp_path / "metrics.md"
        report.to_markdown(path)
        content = path.read_text(encoding="utf-8")
        assert "report_test_dataset" in content
