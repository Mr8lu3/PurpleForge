"""Scenario execution runners.

Importing this package registers all built-in step handlers with the plugin
registry via the side-effect import of ``builtin_handlers``.
"""

# Side-effect import: decorators in builtin_handlers fire here, registering
# the three built-in step types before any WebRunner is instantiated.
import purpleforge.runners.builtin_handlers  # noqa: F401

from purpleforge.runners.web import WebRunner

__all__ = [
    "WebRunner",
]
