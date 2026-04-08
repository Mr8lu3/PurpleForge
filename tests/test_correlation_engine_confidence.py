"""Integration tests for confidence scoring in the correlation engine."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

from purpleforge.correlation.engine import CorrelationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_run_dir():
    """Create a minimal run directory structure and clean up afterwards."""
    tmp = Path(tempfile.mkdtemp())
    run_dir = tmp / "runs" / "test-run-001"
    for subdir in ("correlation", "ground_truth", "telemetry"):
        (run_dir / subdir).mkdir(parents=True)
    # workspace manager expects meta.json to exist
    (run_dir / "meta.json").write_text(
        json.dumps({
            "run_id": "test-run-001",
            "tool_version": "0.1.0",
            "started_at": "2024-01-01T00:00:00",
            "completed_at": None,
            "status": "running",
            "operator_acknowledgements": [],
            "target_verification": {"status": "verified", "checked_at": "2024-01-01T00:00:00", "method": "http_wellknown"},
            "scenario_hash": "abc123",
            "config_hash": "def456",
            "platform": {"os": "Windows", "os_version": "11", "python_version": "3.11.0"},
        }),
        encoding="utf-8",
    )
    yield run_dir
    shutil.rmtree(tmp)


def _write_ground_truth(run_dir: Path, entries: list[Dict[str, Any]]) -> None:
    gt_path = run_dir / "ground_truth" / "expected_evidence.jsonl"
    with open(gt_path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def _write_web_requests(run_dir: Path, entries: list[Dict[str, Any]]) -> None:
    wr_path = run_dir / "telemetry" / "web_requests.jsonl"
    with open(wr_path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Synthetic scenario helpers
# ---------------------------------------------------------------------------

_STEP_A_TIMESTAMP = "2024-01-01T10:00:00"
_STEP_B_TIMESTAMP = "2024-01-01T10:05:00"

# Step A: close event, high-reliability source → should score Tier A
_GROUND_TRUTH_STEP_A: Dict[str, Any] = {
    "step_id": "step-a",
    "step_type": "http_get_baseline",
    "timestamp": _STEP_A_TIMESTAMP,
    "expected_evidence": ["http_200_response"],
    "success": True,
}

# Step B: distant event, no match within reasonable window → should score Tier C
_GROUND_TRUTH_STEP_B: Dict[str, Any] = {
    "step_id": "step-b",
    "step_type": "reflected_xss_probe_safe",
    "timestamp": _STEP_B_TIMESTAMP,
    "expected_evidence": ["reflection_detected"],
    "success": False,
}

# Event matching step-a: timestamp identical (delta=0), source=web_requests(high)
_EVENT_STEP_A_CLOSE: Dict[str, Any] = {
    "timestamp": _STEP_A_TIMESTAMP,
    "step_id": "step-a",
    "method": "GET",
    "url": "http://example.com/",
    "status_code": 200,
    "response_length": 1234,
}

# Event matching step-b: timestamp 290 seconds after step-b (near edge of window),
# source=web_requests but the scoring uses heuristic field match (engine default).
# At delta=290s with window=300: temporal=1-290/300=0.0333
# base = 0.5*0.0333 + 0.3*0.5 + 0.2*1.0 = 0.0167+0.15+0.2 = 0.367 → Tier C
_EVENT_STEP_B_DISTANT: Dict[str, Any] = {
    "timestamp": "2024-01-01T10:09:50",  # 290s after step-b at 10:05:00
    "step_id": "step-b",
    "method": "GET",
    "url": "http://example.com/xss?q=<script>",
    "status_code": 200,
    "response_length": 512,
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEngineConfidenceAnnotation:
    """Engine annotates timeline events with confidence + quality_tier."""

    def test_timeline_events_have_confidence_field(self, temp_run_dir):
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE])

        engine = CorrelationEngine(temp_run_dir)
        result = engine.correlate()

        evidence_events = [e for e in result["timeline"] if e["type"] == "evidence"]
        assert len(evidence_events) == 1
        ev = evidence_events[0]
        assert "confidence" in ev
        assert "quality_tier" in ev
        assert "confidence_breakdown" in ev

    def test_close_high_source_event_is_tier_a(self, temp_run_dir):
        """An event with delta=0 and high-reliability source must achieve Tier A."""
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE])

        engine = CorrelationEngine(temp_run_dir)
        result = engine.correlate()

        evidence_events = [e for e in result["timeline"] if e["type"] == "evidence"]
        ev = evidence_events[0]
        # With delta=0, exact source=high, field=heuristic (default), count=1:
        # base = 0.5*1 + 0.3*0.5 + 0.2*1 = 0.5+0.15+0.2 = 0.85 → Tier A
        assert ev["quality_tier"] == "A"
        assert ev["confidence"] >= 0.8

    def test_distant_event_is_tier_c(self, temp_run_dir):
        """An event far outside the correlation window must yield Tier C."""
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_B])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_B_DISTANT])

        engine = CorrelationEngine(temp_run_dir)
        result = engine.correlate()

        evidence_events = [e for e in result["timeline"] if e["type"] == "evidence"]
        ev = evidence_events[0]
        # delta=290s: temporal = 1-290/300 = 0.0333
        # base = 0.5*0.0333 + 0.3*0.5 + 0.2*1.0 = 0.367 → Tier C
        assert ev["quality_tier"] == "C"
        assert ev["confidence"] < 0.55

    def test_two_steps_mix_tiers(self, temp_run_dir):
        """Verify the engine handles multiple steps with different tier outcomes."""
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A, _GROUND_TRUTH_STEP_B])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE, _EVENT_STEP_B_DISTANT])

        engine = CorrelationEngine(temp_run_dir)
        result = engine.correlate()

        coverage = result["coverage"]
        step_map = {s["step_id"]: s for s in coverage["step_coverage"]}

        assert step_map["step-a"]["quality_tier"] == "A"
        assert step_map["step-b"]["quality_tier"] == "C"


class TestCoverageAggregateFields:
    """coverage.json must contain the new aggregate confidence fields."""

    def test_aggregate_fields_present(self, temp_run_dir):
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE])

        engine = CorrelationEngine(temp_run_dir)
        result = engine.correlate()
        coverage = result["coverage"]

        assert "coverage_confidence_mean" in coverage
        assert "coverage_confidence_median" in coverage
        assert "tier_distribution" in coverage

    def test_tier_distribution_has_all_keys(self, temp_run_dir):
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE])

        engine = CorrelationEngine(temp_run_dir)
        result = engine.correlate()
        td = result["coverage"]["tier_distribution"]

        assert set(td.keys()) == {"A", "B", "C", "none"}

    def test_aggregate_values_are_floats(self, temp_run_dir):
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE])

        engine = CorrelationEngine(temp_run_dir)
        result = engine.correlate()
        coverage = result["coverage"]

        assert isinstance(coverage["coverage_confidence_mean"], float)
        assert isinstance(coverage["coverage_confidence_median"], float)

    def test_persisted_coverage_json_has_aggregate_fields(self, temp_run_dir):
        """Ensure the on-disk coverage.json also carries the new fields."""
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE])

        CorrelationEngine(temp_run_dir).correlate()

        with open(temp_run_dir / "correlation" / "coverage.json", encoding="utf-8") as f:
            saved = json.load(f)

        assert "coverage_confidence_mean" in saved
        assert "coverage_confidence_median" in saved
        assert "tier_distribution" in saved


class TestStepCoveragePerStepFields:
    """Each entry in step_coverage must carry the new per-step fields."""

    def test_step_coverage_has_best_confidence(self, temp_run_dir):
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE])

        result = CorrelationEngine(temp_run_dir).correlate()
        step = result["coverage"]["step_coverage"][0]

        assert "best_confidence" in step
        assert isinstance(step["best_confidence"], float)

    def test_step_coverage_has_quality_tier(self, temp_run_dir):
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE])

        result = CorrelationEngine(temp_run_dir).correlate()
        step = result["coverage"]["step_coverage"][0]

        assert "quality_tier" in step
        assert step["quality_tier"] in ("A", "B", "C", "none")

    def test_step_coverage_has_any_evidence_backward_compat(self, temp_run_dir):
        """has_any_evidence preserves the old binary behaviour."""
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE])

        result = CorrelationEngine(temp_run_dir).correlate()
        step = result["coverage"]["step_coverage"][0]

        assert "has_any_evidence" in step
        assert step["has_any_evidence"] is True

    def test_no_evidence_step_tier_is_none(self, temp_run_dir):
        """A step with no matching events must report quality_tier='none'."""
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A])
        # Write no events
        (temp_run_dir / "telemetry" / "web_requests.jsonl").write_text("")

        result = CorrelationEngine(temp_run_dir).correlate()
        step = result["coverage"]["step_coverage"][0]

        assert step["quality_tier"] == "none"
        assert step["best_confidence"] == 0.0
        assert step["has_any_evidence"] is False

    def test_has_evidence_uses_tier_b_threshold(self, temp_run_dir):
        """has_evidence must be True for Tier A, False for Tier C."""
        # Step A close event → Tier A → has_evidence True
        _write_ground_truth(temp_run_dir, [_GROUND_TRUTH_STEP_A, _GROUND_TRUTH_STEP_B])
        _write_web_requests(temp_run_dir, [_EVENT_STEP_A_CLOSE, _EVENT_STEP_B_DISTANT])

        result = CorrelationEngine(temp_run_dir).correlate()
        step_map = {s["step_id"]: s for s in result["coverage"]["step_coverage"]}

        assert step_map["step-a"]["has_evidence"] is True
        assert step_map["step-b"]["has_evidence"] is False
