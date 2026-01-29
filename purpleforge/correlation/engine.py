"""Correlation engine for timeline and coverage analysis."""

import json
from pathlib import Path
from typing import Any, Dict, List

from purpleforge.telemetry import TelemetryCollector
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class CorrelationEngine:
    """Correlate evidence with ground truth and build timeline."""

    def __init__(self, run_dir: Path):
        """
        Initialize correlation engine.

        Args:
            run_dir: Run directory containing telemetry and ground truth
        """
        self.run_dir = run_dir
        self.correlation_dir = run_dir / "correlation"
        self.ground_truth_dir = run_dir / "ground_truth"
        self.telemetry_collector = TelemetryCollector(run_dir)

    def correlate(self) -> Dict[str, Any]:
        """
        Perform correlation analysis.

        Returns:
            Correlation results including timeline and coverage
        """
        logger.info("Starting correlation analysis")

        # Load ground truth
        ground_truth = self._load_ground_truth()

        # Collect normalized events
        events = self.telemetry_collector.normalize_events()

        # Build timeline
        timeline = self._build_timeline(ground_truth, events)

        # Calculate coverage
        coverage = self._calculate_coverage(ground_truth, events)

        # Save results
        self._save_timeline(timeline)
        self._save_coverage(coverage)

        logger.info(
            f"Correlation complete: {len(timeline)} timeline entries, "
            f"{coverage['coverage_percentage']:.1f}% coverage"
        )

        return {
            "timeline": timeline,
            "coverage": coverage,
        }

    def _load_ground_truth(self) -> List[Dict[str, Any]]:
        """Load ground truth entries."""
        ground_truth_path = self.ground_truth_dir / "expected_evidence.jsonl"

        if not ground_truth_path.exists():
            logger.warning("No ground truth file found")
            return []

        entries = []
        with open(ground_truth_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))

        logger.info(f"Loaded {len(entries)} ground truth entries")
        return entries

    def _build_timeline(
        self, ground_truth: List[Dict[str, Any]], events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Build unified timeline from ground truth and events.

        Args:
            ground_truth: Ground truth entries
            events: Normalized event entries

        Returns:
            Unified timeline sorted by timestamp
        """
        timeline = []

        # Add ground truth entries
        for gt in ground_truth:
            timeline.append(
                {
                    "timestamp": gt["timestamp"],
                    "type": "ground_truth",
                    "step_id": gt["step_id"],
                    "step_type": gt["step_type"],
                    "expected_evidence": gt["expected_evidence"],
                    "success": gt["success"],
                }
            )

        # Add events
        for event in events:
            timeline.append(
                {
                    "timestamp": event["timestamp"],
                    "type": "evidence",
                    "event_type": event["event_type"],
                    "step_id": event["step_id"],
                    "data": event["data"],
                }
            )

        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])

        return timeline

    def _calculate_coverage(
        self, ground_truth: List[Dict[str, Any]], events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate coverage metrics.

        Args:
            ground_truth: Ground truth entries
            events: Normalized event entries

        Returns:
            Coverage metrics
        """
        total_steps = len(ground_truth)
        steps_with_evidence = 0

        # Create event lookup by step_id
        events_by_step = {}
        for event in events:
            step_id = event.get("step_id")
            if step_id:
                if step_id not in events_by_step:
                    events_by_step[step_id] = []
                events_by_step[step_id].append(event)

        # Check which steps have evidence
        step_coverage = []
        for gt in ground_truth:
            step_id = gt["step_id"]
            has_evidence = step_id in events_by_step and len(events_by_step[step_id]) > 0

            if has_evidence:
                steps_with_evidence += 1

            step_coverage.append(
                {
                    "step_id": step_id,
                    "step_type": gt["step_type"],
                    "expected_evidence": gt["expected_evidence"],
                    "has_evidence": has_evidence,
                    "evidence_count": len(events_by_step.get(step_id, [])),
                }
            )

        coverage_percentage = (
            (steps_with_evidence / total_steps * 100) if total_steps > 0 else 0.0
        )

        return {
            "total_steps": total_steps,
            "steps_with_evidence": steps_with_evidence,
            "coverage_percentage": coverage_percentage,
            "step_coverage": step_coverage,
        }

    def _save_timeline(self, timeline: List[Dict[str, Any]]) -> None:
        """Save timeline to JSON file."""
        timeline_path = self.correlation_dir / "timeline.json"
        with open(timeline_path, "w", encoding="utf-8") as f:
            json.dump(timeline, f, indent=2, default=str)
        logger.info(f"Timeline saved to {timeline_path}")

    def _save_coverage(self, coverage: Dict[str, Any]) -> None:
        """Save coverage metrics to JSON file."""
        coverage_path = self.correlation_dir / "coverage.json"
        with open(coverage_path, "w", encoding="utf-8") as f:
            json.dump(coverage, f, indent=2, default=str)
        logger.info(f"Coverage saved to {coverage_path}")
