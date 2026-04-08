"""
Pydantic v2 models for PurpleForge campaign schema.

A campaign is an ordered collection of scenarios that execute against
authorized targets only. Stages are linked via dependency declarations
and may share context keys for defensive-assessment correlation.

Ethical constraint: campaigns must only target systems for which the
operator holds explicit written authorization.
"""

from __future__ import annotations

import collections
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

from purpleforge.utils.exceptions import CampaignError


class CampaignStage(BaseModel):
    """A single stage inside a campaign, wrapping one scenario file."""

    id: str = Field(..., description="Unique stage identifier within the campaign.")
    scenario: str = Field(..., description="Relative or absolute path to the scenario YAML.")
    target: str = Field(..., description="Target base URL for this stage.")
    required: bool = Field(
        default=True,
        description="If True and abort_on_failure is set, failure stops the campaign.",
    )
    depends_on: List[str] = Field(
        default_factory=list,
        description="Stage ids that must complete before this stage runs.",
    )
    exports: List[str] = Field(
        default_factory=list,
        description="Context keys this stage writes into shared_context after completion.",
    )
    imports: List[str] = Field(
        default_factory=list,
        description=(
            "Context keys consumed from shared_context. "
            "Actual injection into scenario execution is future work."
        ),
    )

    model_config = {"frozen": False}


class Campaign(BaseModel):
    """
    Complete campaign definition loaded from YAML.

    Validates structural integrity (unique ids, no dependency cycles,
    scenario files exist) before any execution begins.
    """

    name: str
    description: str
    abort_on_failure: bool = Field(
        default=True,
        description="Hard-stop the campaign when a required stage fails.",
    )
    shared_context_keys: List[str] = Field(
        default_factory=list,
        description="Keys that may flow between stages via shared_context.",
    )
    stages: List[CampaignStage]

    # base_dir is set by the loader after construction; not part of YAML schema.
    _base_dir: Optional[Path] = None

    model_config = {"frozen": False}

    @model_validator(mode="after")
    def validate_campaign(self) -> "Campaign":
        """Run all structural checks after field construction."""
        self._check_unique_stage_ids()
        self._check_depends_on_references()
        self._check_no_cycles()
        return self

    def _check_unique_stage_ids(self) -> None:
        ids = [s.id for s in self.stages]
        seen: set[str] = set()
        duplicates: List[str] = []
        for sid in ids:
            if sid in seen:
                duplicates.append(sid)
            seen.add(sid)
        if duplicates:
            raise CampaignError(
                f"Duplicate stage ids in campaign '{self.name}': {duplicates}",
                hint="Each stage must have a unique 'id' field.",
            )

    def _check_depends_on_references(self) -> None:
        valid_ids = {s.id for s in self.stages}
        for stage in self.stages:
            for dep in stage.depends_on:
                if dep not in valid_ids:
                    raise CampaignError(
                        f"Stage '{stage.id}' depends_on unknown stage '{dep}'.",
                        hint="Ensure all depends_on values match existing stage ids.",
                    )

    def _check_no_cycles(self) -> None:
        """Kahn's algorithm to detect cycles."""
        graph: Dict[str, List[str]] = {s.id: list(s.depends_on) for s in self.stages}
        in_degree: Dict[str, int] = {s.id: 0 for s in self.stages}
        for deps in graph.values():
            for dep in deps:
                in_degree[dep] = in_degree.get(dep, 0)  # ensure key exists
        # build reverse: who depends on me
        rdeps: Dict[str, List[str]] = {s.id: [] for s in self.stages}
        for sid, deps in graph.items():
            for dep in deps:
                rdeps[dep].append(sid)

        queue = collections.deque(sid for sid, deg in in_degree.items() if deg == 0)
        # recompute in_degree correctly
        in_degree2: Dict[str, int] = {s.id: 0 for s in self.stages}
        for stage in self.stages:
            for dep in stage.depends_on:
                in_degree2[stage.id] = in_degree2.get(stage.id, 0) + 1

        in_degree = {s.id: len(s.depends_on) for s in self.stages}
        queue = collections.deque(sid for sid, deg in in_degree.items() if deg == 0)
        visited = 0
        while queue:
            sid = queue.popleft()
            visited += 1
            for dependent in rdeps[sid]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if visited != len(self.stages):
            raise CampaignError(
                f"Campaign '{self.name}' contains a dependency cycle.",
                hint="Review depends_on fields; no stage may transitively depend on itself.",
            )

    def topological_order(self) -> List[CampaignStage]:
        """
        Return stages in a valid execution order (Kahn's algorithm).

        Stages with no dependencies come first. Within the same dependency
        level, order is stable (preserving original YAML order).
        """
        stage_map = {s.id: s for s in self.stages}
        in_degree = {s.id: len(s.depends_on) for s in self.stages}
        rdeps: Dict[str, List[str]] = {s.id: [] for s in self.stages}
        for stage in self.stages:
            for dep in stage.depends_on:
                rdeps[dep].append(stage.id)

        # Use a list-based queue sorted by original order for determinism.
        original_order = [s.id for s in self.stages]
        ready = [sid for sid in original_order if in_degree[sid] == 0]
        result: List[CampaignStage] = []
        while ready:
            sid = ready.pop(0)
            result.append(stage_map[sid])
            for dependent in rdeps[sid]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    # Insert in original declaration order.
                    insert_pos = next(
                        (i for i, r in enumerate(ready) if original_order.index(r) > original_order.index(dependent)),
                        len(ready),
                    )
                    ready.insert(insert_pos, dependent)
        return result

    def validate_scenario_files(self, base_dir: Optional[Path] = None) -> None:
        """
        Check that all scenario files referenced by stages exist.

        Parameters
        ----------
        base_dir:
            Directory to resolve relative scenario paths against.
            Defaults to current working directory.

        Raises
        ------
        CampaignError
            If any scenario file is missing.
        """
        resolve_from = base_dir or Path.cwd()
        for stage in self.stages:
            scenario_path = Path(stage.scenario)
            if not scenario_path.is_absolute():
                scenario_path = resolve_from / scenario_path
            if not scenario_path.exists():
                raise CampaignError(
                    f"Stage '{stage.id}' references missing scenario file: {stage.scenario}",
                    hint=f"Ensure the file exists relative to {resolve_from}",
                )


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

class StageStatus(str):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class StageResult(BaseModel):
    """Outcome for one campaign stage."""

    stage_id: str
    run_id: Optional[str] = None
    run_dir: Optional[str] = None
    status: str  # success | failed | skipped
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    skip_reason: Optional[str] = None
    coverage: Optional[Dict[str, Any]] = None

    model_config = {"frozen": False}


class CampaignResult(BaseModel):
    """Aggregated result of a full campaign run."""

    campaign_id: str
    campaign_name: str
    started_at: str
    completed_at: Optional[str] = None
    overall_status: str  # success | partial | failed | aborted
    stages: List[StageResult] = Field(default_factory=list)

    model_config = {"frozen": False}
