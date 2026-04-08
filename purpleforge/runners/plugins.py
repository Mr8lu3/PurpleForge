"""Plugin registry for PurpleForge scenario step handlers.

All step handlers operate on authorized targets only, for defensive assessment
purposes. The registry enforces no exploitation code — handlers may detect
vulnerability indicators but must never exploit them.
"""

import importlib.metadata
import logging
from dataclasses import dataclass
from logging import Logger
from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable

from purpleforge.scenarios.models import ScenarioStep
from purpleforge.utils.logging import get_logger

_registry_logger = get_logger(__name__)


@dataclass
class StepContext:
    """Lightweight context passed to step handlers.

    Handlers must not reach into WebRunner internals beyond this context.
    All operations must target authorized systems only, for defensive assessment.
    """

    base_url: str
    timeout: int
    log_request: Callable[..., None]
    logger: Logger


@runtime_checkable
class StepHandler(Protocol):
    """Protocol that all step handler callables must satisfy.

    The handler mutates ``result`` in place, adding keys such as
    ``status_code`` and ``evidence_collected``. Raise on failure so the
    caller's try/except boundary can record the error cleanly.
    """

    def __call__(
        self,
        step: ScenarioStep,
        result: Dict[str, Any],
        ctx: StepContext,
    ) -> None:
        """Execute the step handler.

        Args:
            step: The scenario step being executed.
            result: Mutable result dict; add output keys here.
            ctx: Execution context with bound helpers.
        """
        ...


class StepPluginRegistry:
    """Registry that maps step-type strings to handler callables.

    Supports two discovery paths:
    - Decorator ``@register("type_name")`` for built-ins registered at import time.
    - ``load_entry_points()`` for installed third-party plugins declared under
      the ``purpleforge.step_handlers`` entry-points group.

    Idempotent: registering the same type twice overwrites with a warning.
    Loading entry points twice is a no-op after the first call.
    """

    def __init__(self) -> None:
        self._handlers: Dict[str, StepHandler] = {}
        self._entry_points_loaded: bool = False

    def register(self, step_type: str) -> Callable[[StepHandler], StepHandler]:
        """Decorator that registers a callable as the handler for ``step_type``.

        Args:
            step_type: The scenario step ``type`` string this handler serves.

        Returns:
            A decorator that registers the callable and returns it unchanged.
        """

        def decorator(fn: StepHandler) -> StepHandler:
            if step_type in self._handlers:
                _registry_logger.warning(
                    "StepPluginRegistry: overwriting existing handler for '%s'",
                    step_type,
                )
            self._handlers[step_type] = fn
            _registry_logger.debug(
                "StepPluginRegistry: registered handler for '%s'", step_type
            )
            return fn

        return decorator

    def get(self, step_type: str) -> Optional[StepHandler]:
        """Return the handler for ``step_type``, or None if unknown.

        Args:
            step_type: Step type string to look up.
        """
        return self._handlers.get(step_type)

    def all_types(self) -> List[str]:
        """Return a sorted list of all registered step-type strings."""
        return sorted(self._handlers.keys())

    def load_entry_points(
        self, group: str = "purpleforge.step_handlers"
    ) -> int:
        """Discover and load installed third-party step handler plugins.

        Iterates ``importlib.metadata.entry_points(group=group)``. Each entry
        point is expected to point to either:
        - A module containing functions already decorated with ``@register``,
          so that importing the module self-registers them; OR
        - A callable that will be registered under the entry-point name.

        A bad plugin never crashes the registry — errors are caught and logged.

        Args:
            group: Entry-points group to scan.

        Returns:
            Number of entry points successfully loaded.
        """
        if self._entry_points_loaded:
            _registry_logger.debug(
                "StepPluginRegistry: entry points already loaded, skipping"
            )
            return 0

        self._entry_points_loaded = True
        eps = importlib.metadata.entry_points(group=group)
        loaded = 0
        failed = 0

        for ep in eps:
            try:
                obj = ep.load()
                # If the loaded object is callable (a handler function), register
                # it under the entry-point name so callers can use it.
                if callable(obj):
                    # Only register if not already present (decorator may have
                    # fired on import of the module that defines the function).
                    if ep.name not in self._handlers:
                        self._handlers[ep.name] = obj  # type: ignore[assignment]
                        _registry_logger.info(
                            "StepPluginRegistry: loaded plugin '%s' from '%s'",
                            ep.name,
                            ep.value,
                        )
                else:
                    # Module/package import — decorators self-registered.
                    _registry_logger.info(
                        "StepPluginRegistry: imported plugin module '%s' from '%s'",
                        ep.name,
                        ep.value,
                    )
                loaded += 1
            except Exception as exc:
                failed += 1
                _registry_logger.error(
                    "StepPluginRegistry: failed to load entry point '%s' (%s): %s",
                    ep.name,
                    ep.value,
                    exc,
                )

        _registry_logger.info(
            "StepPluginRegistry: entry-point load complete — %d loaded, %d failed",
            loaded,
            failed,
        )
        return loaded


# Module-level singleton used by both built-ins and WebRunner.
registry = StepPluginRegistry()

# Convenience alias so callers can write: from purpleforge.runners.plugins import register
register = registry.register
