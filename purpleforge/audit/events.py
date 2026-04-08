"""
purpleforge.audit.events — typed audit event emitter for one run.

Wraps HashChainLog with high-level methods for the events that matter
during a PurpleForge run.  All methods swallow exceptions and log a
warning so that an audit sub-system fault can never abort a run.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from purpleforge.audit.hash_chain import HashChainLog

logger = logging.getLogger(__name__)

_AUDIT_LOG_FILENAME = "run_audit.log.jsonl"


class AuditEmitter:
    """
    Emit typed, hash-chained audit events for one run.

    Parameters
    ----------
    run_dir:
        The run directory.  The audit log is written to
        ``<run_dir>/audit/run_audit.log.jsonl``.
    """

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        audit_dir = run_dir / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        log_path = audit_dir / _AUDIT_LOG_FILENAME
        try:
            self._chain = HashChainLog(log_path)
        except Exception as exc:
            logger.warning("AuditEmitter: failed to initialise chain log: %s", exc)
            self._chain = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Typed event methods
    # ------------------------------------------------------------------

    def run_created(self, run_id: str, scenario_name: str) -> None:
        """Emit a run_created event."""
        self._emit(
            "run_created",
            {"run_id": run_id, "scenario_name": scenario_name},
        )

    def scenario_loaded(self, scenario_name: str, sha256: str) -> None:
        """Emit a scenario_loaded event with content hash."""
        self._emit(
            "scenario_loaded",
            {"scenario_name": scenario_name, "sha256": sha256},
        )

    def target_verified(self, url: str) -> None:
        """Emit a target_verified event."""
        self._emit("target_verified", {"url": url})

    def step_started(self, step_id: str) -> None:
        """Emit a step_started event."""
        self._emit("step_started", {"step_id": step_id})

    def step_completed(self, step_id: str, status: str) -> None:
        """Emit a step_completed event."""
        self._emit("step_completed", {"step_id": step_id, "status": status})

    def run_completed(self, status: str, counts: Optional[Dict[str, Any]] = None) -> None:
        """Emit a run_completed event."""
        payload: Dict[str, Any] = {"status": status}
        if counts:
            payload["counts"] = counts
        self._emit("run_completed", payload)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit(self, event_type: str, data: Dict[str, Any]) -> None:
        """Build the payload and append to the chain log.  Never raises."""
        if self._chain is None:
            return
        payload: Dict[str, Any] = {
            "event": event_type,
            "ts": datetime.now(timezone.utc).isoformat(),
            **data,
        }
        try:
            self._chain.append(payload)
        except Exception as exc:
            logger.warning(
                "AuditEmitter: failed to write event %r: %s", event_type, exc
            )
