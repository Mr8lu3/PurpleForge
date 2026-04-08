"""
Pure metric computation functions for the PurpleForge evaluation framework.

All functions in this module are **pure**: no I/O, no logging, no randomness,
no side effects. They operate over a flat list of observation dicts produced
by :class:`purpleforge.evaluation.runner.EvaluationRunner`.

For authorized defensive evaluation against labelled datasets only.

Observation dict schema
-----------------------
Each observation is a plain ``dict`` with the following keys:

    item_id         str   — unique identifier for the dataset item
    step_id         str   — step ID within the scenario
    should_detect   bool  — ground-truth label (True = positive class)
    detected        bool  — whether the runner produced a match
    confidence      float — best_confidence from coverage.json (0..1)
    tier            str   — quality_tier from coverage.json ("A"/"B"/"C"/"none")
    mttd_seconds    float | None — seconds from step ground-truth ts to first
                    evidence ts; None when the step was not detected
    run_index       int   — 0-based index of the repetition run

Positive classification rule
-----------------------------
A detection is treated as a **positive** (i.e. "detected") when::

    detected == True AND confidence >= TIER_B_THRESHOLD (0.55)

This mirrors the tier-B threshold used by the correlation engine.
"""

from __future__ import annotations

import statistics
from typing import Any, Callable, Dict, List, Optional

# Mirrors the tier-B threshold from purpleforge.correlation.engine.
TIER_B_THRESHOLD: float = 0.55


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_positive(obs: Dict[str, Any]) -> bool:
    """Return True if the observation is a classified positive."""
    return bool(obs.get("detected", False)) and float(obs.get("confidence", 0.0)) >= TIER_B_THRESHOLD


def _is_ground_truth_positive(obs: Dict[str, Any]) -> bool:
    """Return True if the observation's ground-truth label is positive."""
    return bool(obs.get("should_detect", False))


# ---------------------------------------------------------------------------
# Confusion matrix
# ---------------------------------------------------------------------------


def confusion_matrix(observations: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Compute a binary confusion matrix over *observations*.

    A "positive" prediction requires ``detected == True AND confidence >= 0.55``.
    Ground-truth positive is ``should_detect == True``.

    Parameters
    ----------
    observations:
        Flat list of observation dicts.

    Returns
    -------
    dict
        Keys: ``tp``, ``fp``, ``tn``, ``fn`` (all int).
    """
    tp = fp = tn = fn = 0
    for obs in observations:
        pred_pos = _is_positive(obs)
        gt_pos = _is_ground_truth_positive(obs)
        if pred_pos and gt_pos:
            tp += 1
        elif pred_pos and not gt_pos:
            fp += 1
        elif not pred_pos and not gt_pos:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


# ---------------------------------------------------------------------------
# Precision / Recall / F1
# ---------------------------------------------------------------------------


def precision(cm: Dict[str, int]) -> float:
    """
    Precision = TP / (TP + FP).

    Returns 0.0 when the denominator is zero.
    """
    denom = cm["tp"] + cm["fp"]
    return cm["tp"] / denom if denom > 0 else 0.0


def recall(cm: Dict[str, int]) -> float:
    """
    Recall = TP / (TP + FN).

    Returns 0.0 when the denominator is zero.
    """
    denom = cm["tp"] + cm["fn"]
    return cm["tp"] / denom if denom > 0 else 0.0


def f1(cm: Dict[str, int]) -> float:
    """
    F1 = 2 * precision * recall / (precision + recall).

    Returns 0.0 when either component is zero.
    """
    p = precision(cm)
    r = recall(cm)
    denom = p + r
    return 2.0 * p * r / denom if denom > 0 else 0.0


# ---------------------------------------------------------------------------
# MTTD statistics
# ---------------------------------------------------------------------------


def mttd_stats(observations: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Compute MTTD (mean time to detect) statistics over true-positive observations.

    Only TP observations (``should_detect == True`` AND classified positive)
    with a non-None ``mttd_seconds`` value are included.

    Parameters
    ----------
    observations:
        Flat list of observation dicts.

    Returns
    -------
    dict
        Keys: ``p50`` (median), ``p95`` (95th percentile via sorted-index),
        ``mean``, ``count``.  All floats; zeros when no TP observations.

    Notes
    -----
    The p95 is computed as ``sorted_values[floor(0.95 * n)]`` (0-based,
    clipped to the last index). This is the "nearest rank" lower method.
    """
    values: List[float] = []
    for obs in observations:
        if _is_ground_truth_positive(obs) and _is_positive(obs):
            mttd = obs.get("mttd_seconds")
            if mttd is not None:
                values.append(float(mttd))

    if not values:
        return {"p50": 0.0, "p95": 0.0, "mean": 0.0, "count": 0.0}

    sorted_vals = sorted(values)
    n = len(sorted_vals)

    p50 = statistics.median(sorted_vals)

    p95_idx = min(int(0.95 * n), n - 1)
    p95 = sorted_vals[p95_idx]

    mean_val = statistics.mean(sorted_vals)

    return {
        "p50": p50,
        "p95": p95,
        "mean": mean_val,
        "count": float(n),
    }


# ---------------------------------------------------------------------------
# False positive rate
# ---------------------------------------------------------------------------


def false_positive_rate(observations: List[Dict[str, Any]]) -> float:
    """
    False positive rate = FP / (FP + TN).

    Returns 0.0 when the denominator is zero (no actual negatives).
    """
    cm = confusion_matrix(observations)
    denom = cm["fp"] + cm["tn"]
    return cm["fp"] / denom if denom > 0 else 0.0


# ---------------------------------------------------------------------------
# Per-technique breakdown
# ---------------------------------------------------------------------------


def per_technique_breakdown(
    observations: List[Dict[str, Any]],
    technique_of: Callable[[str], Optional[str]],
) -> Dict[str, Dict[str, Any]]:
    """
    Stratify metrics by ATT&CK technique.

    Parameters
    ----------
    observations:
        Flat list of observation dicts.
    technique_of:
        Callable mapping a ``step_id`` to an ATT&CK technique string (e.g.
        ``"T1190"``), or ``None`` when the step has no assigned technique.
        Observations with no mapped technique are grouped under ``"unknown"``.

    Returns
    -------
    dict
        Mapping technique string -> ``{precision, recall, f1, mttd_p50, n}``.
    """
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for obs in observations:
        technique = technique_of(obs.get("step_id", "")) or "unknown"
        buckets.setdefault(technique, []).append(obs)

    result: Dict[str, Dict[str, Any]] = {}
    for technique, bucket_obs in buckets.items():
        cm = confusion_matrix(bucket_obs)
        p = precision(cm)
        r = recall(cm)
        f = f1(cm)
        mttd = mttd_stats(bucket_obs)
        result[technique] = {
            "precision": p,
            "recall": r,
            "f1": f,
            "mttd_p50": mttd["p50"],
            "n": len(bucket_obs),
        }

    return result


# ---------------------------------------------------------------------------
# Reproducibility variance
# ---------------------------------------------------------------------------


def reproducibility_variance(observations: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Compute per-(item_id, step_id) variance of detection outcome and confidence
    across run repetitions, then return mean variance across all items.

    Parameters
    ----------
    observations:
        Flat list of observation dicts (may span multiple run_index values).

    Returns
    -------
    dict
        Keys:

        ``detection_variance_mean``
            Mean of per-(item, step) variance of the binary detected flag (0/1).
            A value of 0.0 means perfectly consistent across runs; the maximum
            for a 50/50 split is 0.25.

        ``confidence_variance_mean``
            Mean of per-(item, step) variance of confidence scores.

        ``n_items_with_variance``
            Count of (item_id, step_id) pairs that have variance > 0 in
            either dimension.

    Notes
    -----
    Variance is computed as population variance (``statistics.pvariance``),
    consistent with treating the observed runs as the full population rather
    than a sample.  For binary outcomes, the maximum population variance is
    0.25 (equal split between 0 and 1).
    """
    # Group by (item_id, step_id).
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for obs in observations:
        key = (obs.get("item_id", ""), obs.get("step_id", ""))
        groups.setdefault(key, []).append(obs)

    detection_variances: List[float] = []
    confidence_variances: List[float] = []
    n_with_variance = 0

    for _key, group in groups.items():
        if len(group) < 2:
            # Single observation — variance is undefined / 0.
            detection_variances.append(0.0)
            confidence_variances.append(0.0)
            continue

        det_vals = [1.0 if _is_positive(o) else 0.0 for o in group]
        conf_vals = [float(o.get("confidence", 0.0)) for o in group]

        dv = statistics.pvariance(det_vals)
        cv = statistics.pvariance(conf_vals)

        detection_variances.append(dv)
        confidence_variances.append(cv)

        if dv > 0 or cv > 0:
            n_with_variance += 1

    if not detection_variances:
        return {
            "detection_variance_mean": 0.0,
            "confidence_variance_mean": 0.0,
            "n_items_with_variance": 0.0,
        }

    return {
        "detection_variance_mean": statistics.mean(detection_variances),
        "confidence_variance_mean": statistics.mean(confidence_variances),
        "n_items_with_variance": float(n_with_variance),
    }
