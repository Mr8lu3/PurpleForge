"""
Kill-chain diagram emitter for PurpleForge campaigns.

Produces Mermaid (graph LR) and Graphviz DOT representations of a
campaign's stage dependency graph, enriched with ATT&CK kill-chain
phase groupings where technique mappings are known.

ATT&CK technique-to-tactic mapping is a subset of MITRE ATT&CK Enterprise
v14 (https://attack.mitre.org/). Only ~15 common techniques are included
here; unmapped techniques are grouped under "Unknown".
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

from purpleforge.campaign.models import Campaign, CampaignResult

# ---------------------------------------------------------------------------
# MITRE ATT&CK Enterprise: technique id → tactic name (subset, v14)
# Source: https://attack.mitre.org/
# ---------------------------------------------------------------------------
_TECHNIQUE_TACTIC: Dict[str, str] = {
    "T1595": "Reconnaissance",
    "T1592": "Reconnaissance",
    "T1589": "Reconnaissance",
    "T1190": "Initial Access",
    "T1133": "Initial Access",
    "T1078": "Initial Access",
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1053": "Persistence",
    "T1055": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1110": "Credential Access",
    "T1083": "Discovery",
    "T1018": "Discovery",
    "T1041": "Exfiltration",
    "T1071": "Command and Control",
}

# Status → Mermaid style class
_MERMAID_STYLE: Dict[str, str] = {
    "success": "fill:#2d6a2d,color:#fff,stroke:#1a3d1a",
    "failed": "fill:#8b1a1a,color:#fff,stroke:#5a0000",
    "skipped": "fill:#555,color:#ccc,stroke:#333",
}

# Status → DOT node attributes
_DOT_ATTRS: Dict[str, str] = {
    "success": 'style=filled fillcolor="#2d6a2d" fontcolor="#ffffff"',
    "failed": 'style=filled fillcolor="#8b1a1a" fontcolor="#ffffff"',
    "skipped": 'style=filled fillcolor="#555555" fontcolor="#cccccc"',
}


def _stage_status(stage_id: str, result: CampaignResult) -> str:
    for sr in result.stages:
        if sr.stage_id == stage_id:
            return sr.status
    return "skipped"


def _load_techniques_for_stage(campaign: Campaign, stage_id: str) -> List[str]:
    """
    Try to load att_ck_techniques from the stage's scenario YAML.
    Returns empty list on any error.
    """
    stage = next((s for s in campaign.stages if s.id == stage_id), None)
    if stage is None:
        return []
    try:
        path = Path(stage.scenario)
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.exists():
            return []
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data.get("att_ck_techniques", []) or []
    except Exception:
        return []


def _tactic_for_techniques(techniques: List[str]) -> str:
    """Return the most specific tactic or 'Unknown'."""
    for t in techniques:
        if t in _TECHNIQUE_TACTIC:
            return _TECHNIQUE_TACTIC[t]
        # Try parent (e.g. T1059.001 → T1059)
        parent = t.split(".")[0]
        if parent in _TECHNIQUE_TACTIC:
            return _TECHNIQUE_TACTIC[parent]
    return "Unknown"


def to_mermaid(campaign: Campaign, result: CampaignResult) -> str:
    """
    Emit a Mermaid ``graph LR`` diagram for the campaign.

    Nodes are coloured by stage outcome:
    - success  → green
    - failed   → red
    - skipped  → gray

    Parameters
    ----------
    campaign:
        Validated Campaign model.
    result:
        CampaignResult from CampaignRunner.execute().

    Returns
    -------
    str
        Mermaid diagram source.
    """
    lines: List[str] = ["graph LR"]

    # Node definitions with labels.
    for stage in campaign.stages:
        status = _stage_status(stage.id, result)
        safe_id = stage.id.replace("-", "_").replace(".", "_")
        label = f"{stage.id}\\n[{status}]"
        lines.append(f'    {safe_id}["{label}"]')

    lines.append("")

    # Edges from depends_on.
    for stage in campaign.stages:
        safe_to = stage.id.replace("-", "_").replace(".", "_")
        for dep in stage.depends_on:
            safe_from = dep.replace("-", "_").replace(".", "_")
            lines.append(f"    {safe_from} --> {safe_to}")

    lines.append("")

    # Style classes.
    for status, style in _MERMAID_STYLE.items():
        lines.append(f"    classDef {status} {style}")

    lines.append("")

    # Assign classes to nodes.
    by_status: Dict[str, List[str]] = {"success": [], "failed": [], "skipped": []}
    for stage in campaign.stages:
        status = _stage_status(stage.id, result)
        safe_id = stage.id.replace("-", "_").replace(".", "_")
        by_status.get(status, by_status["skipped"]).append(safe_id)

    for status, nodes in by_status.items():
        if nodes:
            lines.append(f"    class {','.join(nodes)} {status}")

    return "\n".join(lines) + "\n"


def to_dot(campaign: Campaign, result: CampaignResult) -> str:
    """
    Emit a Graphviz DOT diagram for the campaign.

    Nodes are grouped into ATT&CK kill-chain phase subgraphs where
    technique mappings are available.

    Parameters
    ----------
    campaign:
        Validated Campaign model.
    result:
        CampaignResult from CampaignRunner.execute().

    Returns
    -------
    str
        Graphviz DOT source (no external process invoked — pure string).
    """
    lines: List[str] = [
        f'digraph campaign {{',
        f'    label="{_dot_escape(campaign.name)}";',
        '    labelloc=t;',
        '    fontsize=14;',
        '    rankdir=LR;',
        '    node [shape=box fontname="Helvetica" fontsize=11];',
        '',
    ]

    # Group stages by tactic for subgraph clusters.
    tactic_stages: Dict[str, List[str]] = {}
    for stage in campaign.stages:
        techniques = _load_techniques_for_stage(campaign, stage.id)
        tactic = _tactic_for_techniques(techniques)
        tactic_stages.setdefault(tactic, []).append(stage.id)

    cluster_idx = 0
    for tactic, stage_ids in sorted(tactic_stages.items()):
        lines.append(f'    subgraph cluster_{cluster_idx} {{')
        lines.append(f'        label="{_dot_escape(tactic)}";')
        lines.append('        style=dashed;')
        lines.append('        color=gray;')
        for sid in stage_ids:
            status = _stage_status(sid, result)
            attrs = _DOT_ATTRS.get(status, _DOT_ATTRS["skipped"])
            safe_id = _dot_node_id(sid)
            lines.append(f'        {safe_id} [label="{_dot_escape(sid)}\\n{status}" {attrs}];')
        lines.append('    }')
        lines.append('')
        cluster_idx += 1

    # Edges.
    for stage in campaign.stages:
        safe_to = _dot_node_id(stage.id)
        for dep in stage.depends_on:
            safe_from = _dot_node_id(dep)
            lines.append(f'    {safe_from} -> {safe_to};')

    lines.append('}')
    return "\n".join(lines) + "\n"


def write_diagrams(out_dir: Path, campaign: Campaign, result: CampaignResult) -> None:
    """
    Write ``killchain.mmd`` and ``killchain.dot`` to *out_dir*.

    Parameters
    ----------
    out_dir:
        Directory to write diagrams into (created if absent).
    campaign:
        Validated Campaign model.
    result:
        CampaignResult from CampaignRunner.execute().
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    mmd_path = out_dir / "killchain.mmd"
    dot_path = out_dir / "killchain.dot"
    mmd_path.write_text(to_mermaid(campaign, result), encoding="utf-8")
    dot_path.write_text(to_dot(campaign, result), encoding="utf-8")


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _dot_escape(text: str) -> str:
    """Escape double-quotes for DOT labels."""
    return text.replace('"', '\\"')


def _dot_node_id(stage_id: str) -> str:
    """Convert stage id to a safe DOT identifier."""
    return stage_id.replace("-", "_").replace(".", "_")
