"""ATT&CK Navigator layer export functionality."""

import json
from pathlib import Path
from typing import List, Optional

from purpleforge.attack.techniques import AttackTechniqueDatabase


def export_navigator_layer(
    technique_ids: List[str],
    output_path: Path,
    layer_name: str = "PurpleForge Assessment",
    description: str = "Techniques covered by security assessment",
    color: str = "#ff6666",
) -> Path:
    """
    Export ATT&CK Navigator layer JSON file.

    Args:
        technique_ids: List of ATT&CK technique IDs to highlight
        output_path: Path to write the layer JSON
        layer_name: Name for the layer
        description: Layer description
        color: Highlight color for techniques (hex)

    Returns:
        Path to the created layer file
    """
    db = AttackTechniqueDatabase()
    layer = db.export_navigator_layer(
        technique_ids=technique_ids,
        layer_name=layer_name,
        description=description,
    )

    # Update color if custom
    if color != "#ff6666":
        for tech in layer["techniques"]:
            tech["color"] = color
        layer["gradient"]["colors"][1] = color
        layer["legendItems"][0]["color"] = color

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)

    return output_path


def export_run_navigator_layer(
    run_dir: Path,
    scenario_techniques: Optional[List[str]] = None,
) -> Path:
    """
    Export Navigator layer for a specific run.

    Args:
        run_dir: Path to run directory
        scenario_techniques: Optional list of technique IDs (will read from scenario if not provided)

    Returns:
        Path to created layer file
    """
    import yaml

    # Try to read techniques from scenario
    if scenario_techniques is None:
        scenario_path = run_dir / "scenario.yaml"
        if scenario_path.exists():
            with open(scenario_path, "r", encoding="utf-8") as f:
                scenario = yaml.safe_load(f)
            scenario_techniques = scenario.get("att_ck_techniques", [])
        else:
            scenario_techniques = []

    # Read run metadata for layer name
    meta_path = run_dir / "meta.json"
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        run_id = meta.get("run_id", "unknown")
        layer_name = f"PurpleForge Run: {run_id[:8]}"
    else:
        layer_name = "PurpleForge Assessment"

    output_path = run_dir / "attack_navigator_layer.json"
    return export_navigator_layer(
        technique_ids=scenario_techniques,
        output_path=output_path,
        layer_name=layer_name,
        description=f"Techniques covered by PurpleForge run at {run_dir.name}",
    )
