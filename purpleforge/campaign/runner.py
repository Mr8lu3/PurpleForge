"""
CampaignRunner: orchestrates multi-stage scenario execution.

Stages execute in topological order derived from their depends_on
declarations. A shared_context dict flows exports forward between stages
(future work: inject imports into scenario execution). All activity is
logged to campaign.log.jsonl.

Ethical note: all stages must target only authorized systems. This
runner is for defensive assessment only.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from purpleforge.campaign.models import (
    Campaign,
    CampaignResult,
    CampaignStage,
    StageResult,
    StageStatus,
)
from purpleforge.runners.execute import execute_scenario
from purpleforge.utils.exceptions import CampaignError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CampaignRunner:
    """
    Orchestrates campaign stage execution.

    Parameters
    ----------
    campaign:
        Validated Campaign model.
    workspace_dir:
        Workspace root; run dirs land under ``workspace_dir/runs/``.
        Campaign artifacts land under ``workspace_dir/campaigns/<campaign_id>/``.
    base_dir:
        Directory used to resolve relative scenario paths.
        Defaults to current working directory.
    """

    def __init__(
        self,
        campaign: Campaign,
        workspace_dir: Path,
        base_dir: Optional[Path] = None,
    ) -> None:
        self.campaign = campaign
        self.workspace_dir = workspace_dir.resolve()
        self.base_dir = (base_dir or Path.cwd()).resolve()
        self.campaign_id = str(uuid.uuid4())
        self.campaign_dir = self.workspace_dir / "campaigns" / self.campaign_id
        self.campaign_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.campaign_dir / "campaign.log.jsonl"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self) -> CampaignResult:
        """
        Execute all campaign stages in topological order.

        Returns a CampaignResult with per-stage outcomes. Writes
        ``campaigns/<campaign_id>/campaign.json`` under workspace_dir.
        """
        started_at = _now_iso()
        self._log_event("campaign_started", {"campaign_name": self.campaign.name})

        ordered_stages = self.campaign.topological_order()
        stage_results: List[StageResult] = []
        shared_context: Dict[str, Any] = {}

        # Track which stages succeeded for dependency resolution.
        succeeded: Set[str] = set()
        failed_required: Set[str] = set()
        aborted = False

        for stage in ordered_stages:
            if aborted:
                sr = self._make_skipped(stage, "aborted_upstream")
                stage_results.append(sr)
                self._log_event("stage_skipped", {"stage_id": stage.id, "reason": "aborted_upstream"})
                continue

            # Check if any required dependency failed.
            failed_deps = [d for d in stage.depends_on if d in failed_required]
            if failed_deps and self.campaign.abort_on_failure:
                sr = self._make_skipped(stage, f"required dependency failed: {failed_deps}")
                stage_results.append(sr)
                self._log_event("stage_skipped", {"stage_id": stage.id, "reason": f"required dep failed: {failed_deps}"})
                aborted = True
                continue

            # Log imports (future: inject into scenario env).
            if stage.imports:
                available = {k: v for k, v in shared_context.items() if k in stage.imports}
                missing = [k for k in stage.imports if k not in shared_context]
                self._log_event(
                    "stage_imports",
                    {"stage_id": stage.id, "available": list(available.keys()), "missing": missing},
                )

            sr = self._run_stage(stage)
            stage_results.append(sr)

            if sr.status == StageStatus.SUCCESS:
                succeeded.add(stage.id)
                # Promote exports into shared_context.
                coverage = sr.coverage or {}
                for key in stage.exports:
                    if key in coverage:
                        shared_context[key] = coverage[key]
                        self._log_event(
                            "context_export",
                            {"stage_id": stage.id, "key": key, "value": coverage[key]},
                        )
                    else:
                        self._log_event(
                            "context_export_missing",
                            {"stage_id": stage.id, "key": key},
                        )
            else:
                # Stage failed.
                if stage.required and self.campaign.abort_on_failure:
                    failed_required.add(stage.id)
                    aborted = True
                    self._log_event(
                        "campaign_aborted",
                        {"reason": f"required stage '{stage.id}' failed"},
                    )

        # Determine overall status.
        statuses = [sr.status for sr in stage_results]
        if all(s == StageStatus.SUCCESS for s in statuses):
            overall = "success"
        elif StageStatus.FAILED in statuses and aborted:
            overall = "aborted"
        elif StageStatus.FAILED in statuses:
            overall = "partial"
        else:
            overall = "success"

        completed_at = _now_iso()
        result = CampaignResult(
            campaign_id=self.campaign_id,
            campaign_name=self.campaign.name,
            started_at=started_at,
            completed_at=completed_at,
            overall_status=overall,
            stages=stage_results,
        )

        self._write_campaign_json(result)
        self._log_event("campaign_completed", {"overall_status": overall})
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_stage(self, stage: CampaignStage) -> StageResult:
        """Execute a single stage and return its StageResult."""
        started_at = _now_iso()
        self._log_event("stage_started", {"stage_id": stage.id, "target": stage.target})

        scenario_path = Path(stage.scenario)
        if not scenario_path.is_absolute():
            scenario_path = self.base_dir / scenario_path

        try:
            run_dir = execute_scenario(
                scenario_path=scenario_path,
                target=stage.target,
                workspace_dir=self.workspace_dir,
                skip_prompts=True,
            )
            completed_at = _now_iso()

            # Read run_id from meta.json.
            run_id: Optional[str] = None
            meta_path = run_dir / "meta.json"
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    run_id = meta.get("run_id")
                except Exception:
                    pass

            # Load coverage for context export.
            coverage: Optional[Dict[str, Any]] = None
            coverage_path = run_dir / "correlation" / "coverage.json"
            if coverage_path.exists():
                try:
                    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
                except Exception:
                    pass

            self._log_event(
                "stage_completed",
                {"stage_id": stage.id, "run_id": run_id, "status": StageStatus.SUCCESS},
            )

            return StageResult(
                stage_id=stage.id,
                run_id=run_id,
                run_dir=str(run_dir),
                status=StageStatus.SUCCESS,
                started_at=started_at,
                completed_at=completed_at,
                coverage=coverage,
            )

        except Exception as exc:
            completed_at = _now_iso()
            error_msg = str(exc)
            self._log_event(
                "stage_failed",
                {"stage_id": stage.id, "error": error_msg},
            )
            logger.error("Stage '%s' failed: %s", stage.id, error_msg)
            return StageResult(
                stage_id=stage.id,
                status=StageStatus.FAILED,
                started_at=started_at,
                completed_at=completed_at,
                error=error_msg,
            )

    def _make_skipped(self, stage: CampaignStage, reason: str) -> StageResult:
        return StageResult(
            stage_id=stage.id,
            status=StageStatus.SKIPPED,
            started_at=_now_iso(),
            completed_at=_now_iso(),
            skip_reason=reason,
        )

    def _log_event(self, event_type: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Append one JSONL line to campaign.log.jsonl."""
        entry = {
            "ts": _now_iso(),
            "event": event_type,
            **(data or {}),
        }
        try:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception as exc:
            logger.warning("Failed to write campaign log entry: %s", exc)

    def _write_campaign_json(self, result: CampaignResult) -> None:
        """Write campaign.json with result + campaign definition."""
        payload = {
            "campaign": self.campaign.model_dump(),
            "result": result.model_dump(),
        }
        out_path = self.campaign_dir / "campaign.json"
        out_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        logger.info("Campaign JSON written to %s", out_path)
