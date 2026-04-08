"""
Evaluation runner for the PurpleForge evaluation framework.

Orchestrates N repeated runs of each labelled dataset item, collects raw
observations, and returns them for metric computation.

For authorized defensive evaluation against labelled datasets only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict

from purpleforge.evaluation.dataset import LabelledDataset
from purpleforge.utils.exceptions import EvaluationError, RunnerError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)

# Mirrors the tier-B threshold from the correlation engine / metrics module.
_TIER_B_THRESHOLD: float = 0.55


class Observation(TypedDict):
    """Typed dict representing one raw observation produced by the runner."""

    item_id: str
    step_id: str
    should_detect: bool
    detected: bool
    confidence: float
    tier: str
    mttd_seconds: Optional[float]
    run_index: int


def _build_item_id(scenario: str, target: str) -> str:
    """Build a stable item identifier from scenario path and target URL."""
    # Use just the filename stem + a hash prefix of the target for readability.
    stem = Path(scenario).stem
    # Simple deterministic shortening — no crypto needed here.
    target_short = target.replace("://", "_").replace("/", "_").replace(":", "_")[:32]
    return f"{stem}__{target_short}"


def _load_coverage(run_dir: Path) -> Dict[str, Any]:
    """Load coverage.json from a run directory."""
    path = run_dir / "correlation" / "coverage.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load coverage.json from %s: %s", run_dir, exc)
        return {}


def _load_timeline(run_dir: Path) -> List[Dict[str, Any]]:
    """Load timeline.json from a run directory."""
    path = run_dir / "correlation" / "timeline.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load timeline.json from %s: %s", run_dir, exc)
        return []


def _earliest_evidence_timestamp(
    timeline: List[Dict[str, Any]], step_id: str
) -> Optional[str]:
    """Return the earliest evidence event timestamp for *step_id*, or None."""
    candidates: List[str] = [
        entry["timestamp"]
        for entry in timeline
        if entry.get("type") == "evidence"
        and entry.get("step_id") == step_id
        and entry.get("confidence", 0.0) >= _TIER_B_THRESHOLD
    ]
    return min(candidates) if candidates else None


def _ground_truth_timestamp(
    timeline: List[Dict[str, Any]], step_id: str
) -> Optional[str]:
    """Return the ground-truth timestamp for *step_id*, or None."""
    for entry in timeline:
        if entry.get("type") == "ground_truth" and entry.get("step_id") == step_id:
            return entry.get("timestamp")
    return None


def _parse_iso(ts: str) -> Optional[float]:
    """Parse an ISO-8601 timestamp to a POSIX timestamp float."""
    from datetime import datetime, timezone

    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _compute_mttd(
    timeline: List[Dict[str, Any]], step_id: str
) -> Optional[float]:
    """
    Compute MTTD in seconds for *step_id*.

    Returns the difference between the earliest above-threshold evidence
    timestamp and the ground-truth step timestamp. Returns None if either
    timestamp is unavailable.
    """
    gt_ts = _ground_truth_timestamp(timeline, step_id)
    ev_ts = _earliest_evidence_timestamp(timeline, step_id)
    if gt_ts is None or ev_ts is None:
        return None
    gt_epoch = _parse_iso(gt_ts)
    ev_epoch = _parse_iso(ev_ts)
    if gt_epoch is None or ev_epoch is None:
        return None
    return max(0.0, ev_epoch - gt_epoch)


class EvaluationRunner:
    """
    Orchestrate repeated scenario runs and collect raw observations.

    For authorized defensive evaluation against labelled datasets only.

    Parameters
    ----------
    dataset:
        Validated :class:`~purpleforge.evaluation.dataset.LabelledDataset`.
    workspace_dir:
        Root workspace directory where run sub-directories are created.
    runs_per_item:
        Number of times each dataset item is executed. Enables reproducibility
        variance computation. Defaults to 3.
    """

    def __init__(
        self,
        dataset: LabelledDataset,
        workspace_dir: Path,
        runs_per_item: int = 3,
    ) -> None:
        self.dataset = dataset
        self.workspace_dir = workspace_dir
        self.runs_per_item = runs_per_item

    def execute(self) -> List[Observation]:
        """
        Execute all dataset items and return the flat observation list.

        Items that error during execution are skipped with a warning; TN/FN
        placeholder observations are emitted for their expected detections so
        that metric denominators remain correct.
        """
        # Deferred import to avoid circular dependencies and to allow mocking.
        from purpleforge.runners.execute import execute_scenario

        observations: List[Observation] = []

        for item in self.dataset.items:
            item_id = _build_item_id(item.scenario, item.target)
            scenario_path = Path(item.scenario)

            for run_index in range(self.runs_per_item):
                logger.info(
                    "Evaluating item '%s' run %d/%d",
                    item_id,
                    run_index + 1,
                    self.runs_per_item,
                )

                run_dir: Optional[Path] = None
                run_failed = False

                try:
                    run_dir = execute_scenario(
                        scenario_path=scenario_path,
                        target=item.target,
                        workspace_dir=self.workspace_dir,
                        skip_prompts=True,
                    )
                except (RunnerError, EvaluationError) as exc:
                    logger.warning(
                        "Run %d for item '%s' failed: %s — emitting fallback observations.",
                        run_index,
                        item_id,
                        exc,
                    )
                    run_failed = True
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Unexpected error in run %d for item '%s': %s — skipping.",
                        run_index,
                        item_id,
                        exc,
                    )
                    run_failed = True

                if run_failed or run_dir is None:
                    # Emit conservative fallback observations (TN for negatives, FN for positives).
                    for ed in item.expected_detections:
                        observations.append(
                            Observation(
                                item_id=item_id,
                                step_id=ed.step_id,
                                should_detect=ed.should_detect,
                                detected=False,
                                confidence=0.0,
                                tier="none",
                                mttd_seconds=None,
                                run_index=run_index,
                            )
                        )
                    continue

                # Load coverage and timeline for this run.
                coverage = _load_coverage(run_dir)
                timeline = _load_timeline(run_dir)

                # Index step_coverage by step_id for fast lookup.
                step_coverage_by_id: Dict[str, Dict[str, Any]] = {
                    sc["step_id"]: sc
                    for sc in coverage.get("step_coverage", [])
                }

                for ed in item.expected_detections:
                    sc = step_coverage_by_id.get(ed.step_id)

                    if sc is None:
                        # Step not found in coverage — treat as not detected.
                        logger.debug(
                            "step_id '%s' not found in coverage for run %s",
                            ed.step_id,
                            run_dir,
                        )
                        obs: Observation = Observation(
                            item_id=item_id,
                            step_id=ed.step_id,
                            should_detect=ed.should_detect,
                            detected=False,
                            confidence=0.0,
                            tier="none",
                            mttd_seconds=None,
                            run_index=run_index,
                        )
                    else:
                        detected = bool(sc.get("has_evidence", False))
                        confidence = float(sc.get("best_confidence", 0.0))
                        tier = str(sc.get("quality_tier", "none"))
                        mttd: Optional[float] = (
                            _compute_mttd(timeline, ed.step_id) if detected else None
                        )
                        obs = Observation(
                            item_id=item_id,
                            step_id=ed.step_id,
                            should_detect=ed.should_detect,
                            detected=detected,
                            confidence=confidence,
                            tier=tier,
                            mttd_seconds=mttd,
                            run_index=run_index,
                        )

                    observations.append(obs)

        logger.info(
            "Evaluation complete: %d observations from %d items x %d runs",
            len(observations),
            len(self.dataset.items),
            self.runs_per_item,
        )
        return observations
