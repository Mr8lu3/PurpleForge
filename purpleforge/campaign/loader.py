"""
Campaign YAML loader with friendly validation errors.

Ethical note: loaded campaigns must only reference authorized targets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError

from purpleforge.campaign.models import Campaign
from purpleforge.utils.exceptions import CampaignError


def load_campaign(path: Path, *, validate_files: bool = True) -> Campaign:
    """
    Load and validate a campaign YAML file.

    Parameters
    ----------
    path:
        Path to the campaign YAML file.
    validate_files:
        If True (default), check that every referenced scenario file exists.

    Returns
    -------
    Campaign
        Validated Campaign model.

    Raises
    ------
    CampaignError
        On YAML parse errors, schema validation failures, or missing files.
    """
    if not path.exists():
        raise CampaignError(
            f"Campaign file not found: {path}",
            hint="Check the path and ensure the file exists.",
        )

    try:
        with path.open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise CampaignError(
            f"Failed to parse campaign YAML: {exc}",
            hint="Check for syntax errors in the campaign file.",
        ) from exc

    if not isinstance(raw, dict):
        raise CampaignError(
            "Campaign YAML must be a mapping at the top level.",
            hint="Ensure the file starts with key: value pairs, not a list.",
        )

    try:
        campaign = Campaign.model_validate(raw)
    except (ValidationError, CampaignError) as exc:
        if isinstance(exc, CampaignError):
            raise
        raise CampaignError(
            f"Campaign schema validation failed: {exc}",
            hint="Review the campaign YAML against the schema documentation.",
        ) from exc

    if validate_files:
        base_dir = path.parent.resolve()
        campaign.validate_scenario_files(base_dir)

    return campaign
