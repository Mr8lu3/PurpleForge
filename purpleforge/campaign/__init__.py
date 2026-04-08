"""
Campaign mode: multi-scenario sequencing for authorized defensive assessments.

Exports the public API for the campaign subpackage. All campaigns must target
only authorized systems; context sharing between stages is for defensive
assessment only.
"""

from purpleforge.campaign.models import Campaign, CampaignStage, CampaignResult, StageResult
from purpleforge.campaign.runner import CampaignRunner
from purpleforge.campaign.killchain import to_mermaid, to_dot, write_diagrams
from purpleforge.campaign.loader import load_campaign

__all__ = [
    "Campaign",
    "CampaignStage",
    "CampaignResult",
    "StageResult",
    "CampaignRunner",
    "to_mermaid",
    "to_dot",
    "write_diagrams",
    "load_campaign",
]
