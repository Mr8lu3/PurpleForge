"""Configuration management for PurpleForge."""

from purpleforge.config.models import Config, TargetEntry
from purpleforge.config.loader import load_config, save_config, load_targets, save_targets

__all__ = [
    "Config",
    "TargetEntry",
    "load_config",
    "save_config",
    "load_targets",
    "save_targets",
]
