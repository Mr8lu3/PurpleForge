"""Configuration loading and saving."""

import yaml
from pathlib import Path
from typing import Optional

from purpleforge.config.models import Config, TargetAllowlist, TargetEntry
from purpleforge.utils.exceptions import ConfigurationError
from purpleforge.utils.platform import get_user_config_dir


def get_config_path() -> Path:
    """Get the default config file path."""
    return get_user_config_dir() / "config.yml"


def get_targets_path() -> Path:
    """Get the default targets allowlist file path."""
    return get_user_config_dir() / "targets.yml"


def load_config(config_path: Optional[Path] = None) -> Config:
    """
    Load configuration from YAML file.

    Args:
        config_path: Optional path to config file. Defaults to user config dir.

    Returns:
        Config object with validated settings

    Raises:
        ConfigurationError: If config file is invalid or missing
    """
    if config_path is None:
        config_path = get_config_path()

    if not config_path.exists():
        # Return default config if file doesn't exist
        return Config()

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return Config(**data)
    except Exception as e:
        raise ConfigurationError(
            f"Failed to load configuration from {config_path}",
            hint=f"Error: {e}",
        )


def save_config(config: Config, config_path: Optional[Path] = None) -> None:
    """
    Save configuration to YAML file.

    Args:
        config: Config object to save
        config_path: Optional path to config file. Defaults to user config dir.
    """
    if config_path is None:
        config_path = get_config_path()

    config_path.parent.mkdir(parents=True, exist_ok=True)

    data = config.model_dump(mode="python")
    # Convert Path objects to strings for YAML serialization
    data["workspace_dir"] = str(data["workspace_dir"])
    data["scenarios_dir"] = str(data["scenarios_dir"])

    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def load_targets(targets_path: Optional[Path] = None) -> TargetAllowlist:
    """
    Load target allowlist from YAML file.

    Args:
        targets_path: Optional path to targets file. Defaults to user config dir.

    Returns:
        TargetAllowlist with verified targets
    """
    if targets_path is None:
        targets_path = get_targets_path()

    if not targets_path.exists():
        return TargetAllowlist()

    try:
        with open(targets_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return TargetAllowlist(**data)
    except Exception as e:
        raise ConfigurationError(
            f"Failed to load targets from {targets_path}",
            hint=f"Error: {e}",
        )


def save_targets(allowlist: TargetAllowlist, targets_path: Optional[Path] = None) -> None:
    """
    Save target allowlist to YAML file.

    Args:
        allowlist: TargetAllowlist to save
        targets_path: Optional path to targets file. Defaults to user config dir.
    """
    if targets_path is None:
        targets_path = get_targets_path()

    targets_path.parent.mkdir(parents=True, exist_ok=True)

    data = allowlist.model_dump(mode="python")

    with open(targets_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
