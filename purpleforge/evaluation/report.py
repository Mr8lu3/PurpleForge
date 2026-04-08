"""
Evaluation report generator for the PurpleForge evaluation framework.

Produces JSON, LaTeX, and Markdown outputs from computed metrics.

For authorized defensive evaluation against labelled datasets only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from purpleforge.evaluation.dataset import LabelledDataset
from purpleforge.evaluation.metrics import (
    confusion_matrix,
    f1,
    false_positive_rate,
    mttd_stats,
    per_technique_breakdown,
    precision,
    recall,
    reproducibility_variance,
)
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


def _fmt(value: float, decimals: int = 4) -> str:
    """Format a float to *decimals* places as a string."""
    return f"{value:.{decimals}f}"


def _latex_escape(text: str) -> str:
    """Escape characters that have special meaning in LaTeX."""
    replacements = [
        ("\\", "\\textbackslash{}"),
        ("&", "\\&"),
        ("%", "\\%"),
        ("$", "\\$"),
        ("#", "\\#"),
        ("_", "\\_"),
        ("{", "\\{"),
        ("}", "\\}"),
        ("~", "\\textasciitilde{}"),
        ("^", "\\textasciicircum{}"),
    ]
    for char, escaped in replacements:
        text = text.replace(char, escaped)
    return text


class EvaluationReport:
    """
    Assemble and emit evaluation metrics in multiple formats.

    For authorized defensive evaluation against labelled datasets only.

    Parameters
    ----------
    observations:
        Flat list of observation dicts from
        :class:`~purpleforge.evaluation.runner.EvaluationRunner`.
    dataset:
        The :class:`~purpleforge.evaluation.dataset.LabelledDataset` that was
        evaluated (used for metadata in reports).
    """

    def __init__(
        self,
        observations: List[Dict[str, Any]],
        dataset: LabelledDataset,
    ) -> None:
        self.observations = observations
        self.dataset = dataset
        self._computed: Optional[Dict[str, Any]] = None

    def _technique_of(self, step_id: str) -> Optional[str]:
        """
        Look up the ATT&CK technique for a step_id.

        Checks per-item ``att_ck_technique_map`` first; if absent, falls back
        to the scenario's ``att_ck_techniques`` list (using the first entry
        since the schema maps techniques to the whole scenario, not per step).
        Returns None when no mapping is found.
        """
        for item in self.dataset.items:
            if step_id in item.att_ck_technique_map:
                return item.att_ck_technique_map[step_id]
        # Fallback: return None (technique unknown at step level).
        return None

    def compute_all(self) -> Dict[str, Any]:
        """
        Compute and cache all metrics.

        Returns
        -------
        dict
            Nested dict with keys: ``overall``, ``per_technique``,
            ``mttd``, ``reproducibility``, ``false_positive_rate``,
            ``dataset_meta``.
        """
        if self._computed is not None:
            return self._computed

        cm = confusion_matrix(self.observations)
        p = precision(cm)
        r = recall(cm)
        f = f1(cm)
        mttd = mttd_stats(self.observations)
        repro = reproducibility_variance(self.observations)
        fpr = false_positive_rate(self.observations)
        per_tech = per_technique_breakdown(self.observations, self._technique_of)

        self._computed = {
            "dataset_meta": {
                "name": self.dataset.name,
                "description": self.dataset.description,
                "n_items": len(self.dataset.items),
                "n_observations": len(self.observations),
            },
            "overall": {
                "confusion_matrix": cm,
                "precision": p,
                "recall": r,
                "f1": f,
            },
            "mttd": mttd,
            "reproducibility": repro,
            "false_positive_rate": fpr,
            "per_technique": per_tech,
        }
        return self._computed

    def to_json(self, path: Path) -> None:
        """
        Write computed metrics to *path* as pretty-printed UTF-8 JSON.

        Key order is deterministic (sorted).
        """
        metrics = self.compute_all()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(metrics, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Metrics JSON written to %s", path)

    def to_latex_table(self, path: Path) -> None:
        """
        Write a LaTeX ``tabular`` fragment to *path*.

        The fragment contains only the ``tabular`` environment — no
        ``\\documentclass`` wrapper — suitable for ``\\input{}`` inclusion.

        Special characters (``%``, ``_``, etc.) are escaped automatically.
        """
        metrics = self.compute_all()
        overall = metrics["overall"]
        mttd = metrics["mttd"]
        repro = metrics["reproducibility"]
        fpr = metrics["false_positive_rate"]

        def row(label: str, value: str) -> str:
            return f"  {_latex_escape(label)} & {_latex_escape(value)} \\\\"

        lines = [
            "% Generated by PurpleForge Phase 5 evaluation framework",
            "\\begin{tabular}{ll}",
            "  \\hline",
            "  \\textbf{Metric} & \\textbf{Value} \\\\",
            "  \\hline",
            row("Precision", _fmt(overall["precision"])),
            row("Recall", _fmt(overall["recall"])),
            row("F1 Score", _fmt(overall["f1"])),
            row("MTTD p50 (s)", _fmt(mttd["p50"], 2)),
            row("MTTD p95 (s)", _fmt(mttd["p95"], 2)),
            row("MTTD mean (s)", _fmt(mttd["mean"], 2)),
            row("MTTD count", str(int(mttd["count"]))),
            row("Detection variance (mean)", _fmt(repro["detection_variance_mean"])),
            row("Confidence variance (mean)", _fmt(repro["confidence_variance_mean"])),
            row("Items with variance", str(int(repro["n_items_with_variance"]))),
            row("False positive rate", _fmt(fpr)),
            row("TP", str(overall["confusion_matrix"]["tp"])),
            row("FP", str(overall["confusion_matrix"]["fp"])),
            row("TN", str(overall["confusion_matrix"]["tn"])),
            row("FN", str(overall["confusion_matrix"]["fn"])),
            "  \\hline",
            "\\end{tabular}",
        ]

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info("Metrics LaTeX table written to %s", path)

    def to_markdown(self, path: Path) -> None:
        """
        Write a human-readable Markdown summary to *path*.

        Suitable for inclusion in a run report or coursework appendix.
        """
        metrics = self.compute_all()
        overall = metrics["overall"]
        mttd = metrics["mttd"]
        repro = metrics["reproducibility"]
        fpr = metrics["false_positive_rate"]
        cm = overall["confusion_matrix"]
        meta = metrics["dataset_meta"]

        lines = [
            f"# PurpleForge Evaluation Metrics — {meta['name']}",
            "",
            f"> {meta['description']}",
            "",
            f"**Dataset:** {meta['n_items']} items, {meta['n_observations']} observations",
            "",
            "## Overall Detection Performance",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Precision | {_fmt(overall['precision'])} |",
            f"| Recall | {_fmt(overall['recall'])} |",
            f"| F1 Score | {_fmt(overall['f1'])} |",
            f"| False Positive Rate | {_fmt(fpr)} |",
            "",
            "## Confusion Matrix",
            "",
            "| | Predicted Positive | Predicted Negative |",
            "|---|---|---|",
            f"| Actual Positive | TP = {cm['tp']} | FN = {cm['fn']} |",
            f"| Actual Negative | FP = {cm['fp']} | TN = {cm['tn']} |",
            "",
            "## Mean Time to Detect (MTTD)",
            "",
            "| Statistic | Value (s) |",
            "|-----------|-----------|",
            f"| p50 (median) | {_fmt(mttd['p50'], 2)} |",
            f"| p95 | {_fmt(mttd['p95'], 2)} |",
            f"| Mean | {_fmt(mttd['mean'], 2)} |",
            f"| Count (TP detections) | {int(mttd['count'])} |",
            "",
            "## Reproducibility",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Detection variance mean | {_fmt(repro['detection_variance_mean'])} |",
            f"| Confidence variance mean | {_fmt(repro['confidence_variance_mean'])} |",
            f"| Items with variance > 0 | {int(repro['n_items_with_variance'])} |",
            "",
            "## Per-Technique Breakdown",
            "",
        ]

        per_tech = metrics.get("per_technique", {})
        if per_tech:
            lines += [
                "| Technique | Precision | Recall | F1 | MTTD p50 (s) | n |",
                "|-----------|-----------|--------|----|--------------|---|",
            ]
            for technique, t_metrics in sorted(per_tech.items()):
                lines.append(
                    f"| {technique} "
                    f"| {_fmt(t_metrics['precision'])} "
                    f"| {_fmt(t_metrics['recall'])} "
                    f"| {_fmt(t_metrics['f1'])} "
                    f"| {_fmt(t_metrics['mttd_p50'], 2)} "
                    f"| {t_metrics['n']} |"
                )
        else:
            lines.append("_No per-technique data available._")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info("Metrics Markdown written to %s", path)
