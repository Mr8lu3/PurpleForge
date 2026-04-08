"""
Tests for purpleforge.evaluation.metrics.

All functions under test are pure: no I/O, no side effects.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from purpleforge.evaluation.metrics import (
    TIER_B_THRESHOLD,
    confusion_matrix,
    f1,
    false_positive_rate,
    mttd_stats,
    per_technique_breakdown,
    precision,
    recall,
    reproducibility_variance,
)

# ---------------------------------------------------------------------------
# Helpers to build observation dicts
# ---------------------------------------------------------------------------


def _obs(
    *,
    item_id: str = "item1",
    step_id: str = "step1",
    should_detect: bool = True,
    detected: bool = True,
    confidence: float = 0.9,
    tier: str = "A",
    mttd_seconds: Optional[float] = 10.0,
    run_index: int = 0,
) -> Dict[str, Any]:
    return {
        "item_id": item_id,
        "step_id": step_id,
        "should_detect": should_detect,
        "detected": detected,
        "confidence": confidence,
        "tier": tier,
        "mttd_seconds": mttd_seconds,
        "run_index": run_index,
    }


def _tp(**kw: Any) -> Dict[str, Any]:
    """True positive: should_detect=True, detected=True, high confidence."""
    kw.setdefault("should_detect", True)
    kw.setdefault("detected", True)
    kw.setdefault("confidence", 0.9)
    kw.setdefault("mttd_seconds", 10.0)
    return _obs(**kw)


def _fn(**kw: Any) -> Dict[str, Any]:
    """False negative: should_detect=True, detected=False."""
    kw.setdefault("should_detect", True)
    kw.setdefault("detected", False)
    kw.setdefault("confidence", 0.1)
    kw.setdefault("mttd_seconds", None)
    return _obs(**kw)


def _fp(**kw: Any) -> Dict[str, Any]:
    """False positive: should_detect=False, detected=True, high confidence."""
    kw.setdefault("should_detect", False)
    kw.setdefault("detected", True)
    kw.setdefault("confidence", 0.9)
    kw.setdefault("mttd_seconds", None)
    return _obs(**kw)


def _tn(**kw: Any) -> Dict[str, Any]:
    """True negative: should_detect=False, detected=False."""
    kw.setdefault("should_detect", False)
    kw.setdefault("detected", False)
    kw.setdefault("confidence", 0.1)
    kw.setdefault("mttd_seconds", None)
    return _obs(**kw)


# ---------------------------------------------------------------------------
# Confusion matrix tests
# ---------------------------------------------------------------------------


class TestConfusionMatrix:
    def test_all_tp(self) -> None:
        obs = [_tp(), _tp(step_id="step2"), _tp(step_id="step3")]
        cm = confusion_matrix(obs)
        assert cm == {"tp": 3, "fp": 0, "tn": 0, "fn": 0}

    def test_all_fn(self) -> None:
        obs = [_fn(), _fn(step_id="step2")]
        cm = confusion_matrix(obs)
        assert cm == {"tp": 0, "fp": 0, "tn": 0, "fn": 2}

    def test_all_fp(self) -> None:
        obs = [_fp(), _fp(step_id="step2")]
        cm = confusion_matrix(obs)
        assert cm == {"tp": 0, "fp": 2, "tn": 0, "fn": 0}

    def test_all_tn(self) -> None:
        obs = [_tn(), _tn(step_id="step2")]
        cm = confusion_matrix(obs)
        assert cm == {"tp": 0, "fp": 0, "tn": 2, "fn": 0}

    def test_mixed(self) -> None:
        obs = [_tp(), _fn(), _fp(), _tn()]
        cm = confusion_matrix(obs)
        assert cm == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}

    def test_tier_b_boundary_just_above(self) -> None:
        # confidence == 0.55 exactly → positive (>= threshold).
        obs = [_obs(should_detect=True, detected=True, confidence=TIER_B_THRESHOLD)]
        cm = confusion_matrix(obs)
        assert cm["tp"] == 1

    def test_tier_b_boundary_just_below(self) -> None:
        # confidence < 0.55 → NOT a positive, so it's a FN.
        obs = [_obs(should_detect=True, detected=True, confidence=TIER_B_THRESHOLD - 0.001)]
        cm = confusion_matrix(obs)
        assert cm["fn"] == 1

    def test_empty(self) -> None:
        cm = confusion_matrix([])
        assert cm == {"tp": 0, "fp": 0, "tn": 0, "fn": 0}


# ---------------------------------------------------------------------------
# Precision / Recall / F1 tests
# ---------------------------------------------------------------------------


class TestPrecisionRecallF1:
    def test_perfect(self) -> None:
        obs = [_tp(), _tp(step_id="s2")]
        cm = confusion_matrix(obs)
        assert precision(cm) == pytest.approx(1.0)
        assert recall(cm) == pytest.approx(1.0)
        assert f1(cm) == pytest.approx(1.0)

    def test_zero_guard_precision(self) -> None:
        # No TP or FP → precision denominator is 0.
        cm = {"tp": 0, "fp": 0, "tn": 5, "fn": 3}
        assert precision(cm) == pytest.approx(0.0)

    def test_zero_guard_recall(self) -> None:
        # No TP or FN → recall denominator is 0.
        cm = {"tp": 0, "fp": 3, "tn": 2, "fn": 0}
        assert recall(cm) == pytest.approx(0.0)

    def test_zero_guard_f1(self) -> None:
        cm = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        assert f1(cm) == pytest.approx(0.0)

    def test_mixed_values(self) -> None:
        # TP=2, FP=1, TN=1, FN=1
        cm = {"tp": 2, "fp": 1, "tn": 1, "fn": 1}
        p = 2 / 3
        r = 2 / 3
        expected_f1 = 2 * p * r / (p + r)
        assert precision(cm) == pytest.approx(p, rel=1e-6)
        assert recall(cm) == pytest.approx(r, rel=1e-6)
        assert f1(cm) == pytest.approx(expected_f1, rel=1e-6)

    def test_all_fp_precision_zero(self) -> None:
        obs = [_fp(), _fp(step_id="s2")]
        cm = confusion_matrix(obs)
        assert precision(cm) == pytest.approx(0.0)

    def test_all_fn_recall_zero(self) -> None:
        obs = [_fn(), _fn(step_id="s2")]
        cm = confusion_matrix(obs)
        assert recall(cm) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# MTTD statistics tests
# ---------------------------------------------------------------------------


class TestMttdStats:
    def test_known_distribution(self) -> None:
        # 1..100 → p50 should be median of sorted list = 50.5 (statistics.median)
        # p95 via floor(0.95 * 100) = 95, sorted_vals[95] = 96 (0-indexed from 1).
        obs = [
            _tp(step_id=f"step{i}", mttd_seconds=float(i))
            for i in range(1, 101)
        ]
        stats = mttd_stats(obs)
        # statistics.median of [1..100] = 50.5
        assert stats["p50"] == pytest.approx(50.5)
        # floor(0.95 * 100) = 95 → sorted_vals[95] = 96
        assert stats["p95"] == pytest.approx(96.0)
        assert stats["mean"] == pytest.approx(50.5)
        assert stats["count"] == pytest.approx(100.0)

    def test_single_value(self) -> None:
        obs = [_tp(mttd_seconds=30.0)]
        stats = mttd_stats(obs)
        assert stats["p50"] == pytest.approx(30.0)
        assert stats["p95"] == pytest.approx(30.0)
        assert stats["mean"] == pytest.approx(30.0)
        assert stats["count"] == pytest.approx(1.0)

    def test_excludes_fn(self) -> None:
        # FN has mttd_seconds — must be excluded.
        obs = [_fn(mttd_seconds=5.0), _tp(mttd_seconds=20.0)]
        stats = mttd_stats(obs)
        # Only the TP contributes.
        assert stats["count"] == pytest.approx(1.0)
        assert stats["p50"] == pytest.approx(20.0)

    def test_excludes_fp_tn(self) -> None:
        obs = [_fp(mttd_seconds=5.0), _tn(mttd_seconds=3.0)]
        stats = mttd_stats(obs)
        assert stats["count"] == pytest.approx(0.0)
        assert stats["p50"] == pytest.approx(0.0)

    def test_excludes_none_mttd(self) -> None:
        # TP with no mttd_seconds is excluded.
        obs = [_tp(mttd_seconds=None), _tp(step_id="s2", mttd_seconds=40.0)]
        stats = mttd_stats(obs)
        assert stats["count"] == pytest.approx(1.0)

    def test_empty_returns_zeros(self) -> None:
        stats = mttd_stats([])
        assert stats == {"p50": 0.0, "p95": 0.0, "mean": 0.0, "count": 0.0}


# ---------------------------------------------------------------------------
# Reproducibility variance tests
# ---------------------------------------------------------------------------


class TestReproducibilityVariance:
    def test_all_identical_runs_zero_variance(self) -> None:
        """
        All runs produce identical outcomes → variance must be 0.0.
        """
        obs = [
            _tp(item_id="i1", step_id="s1", run_index=0, confidence=0.8),
            _tp(item_id="i1", step_id="s1", run_index=1, confidence=0.8),
            _tp(item_id="i1", step_id="s1", run_index=2, confidence=0.8),
        ]
        result = reproducibility_variance(obs)
        assert result["detection_variance_mean"] == pytest.approx(0.0)
        assert result["confidence_variance_mean"] == pytest.approx(0.0)
        assert result["n_items_with_variance"] == pytest.approx(0.0)

    def test_alternating_detection_variance(self) -> None:
        """
        Alternating detected=True/False over two runs.

        Binary population variance: values = [1, 0], mean = 0.5,
        pvariance = ((1 - 0.5)^2 + (0 - 0.5)^2) / 2 = 0.25.
        """
        obs = [
            _obs(
                item_id="i1",
                step_id="s1",
                should_detect=True,
                detected=True,
                confidence=0.9,
                run_index=0,
            ),
            _obs(
                item_id="i1",
                step_id="s1",
                should_detect=True,
                detected=False,
                confidence=0.3,
                run_index=1,
            ),
        ]
        result = reproducibility_variance(obs)
        # The classified positives are [1, 0] (confidence 0.9 >= 0.55; 0.3 < 0.55).
        assert result["detection_variance_mean"] == pytest.approx(0.25)
        assert result["n_items_with_variance"] == pytest.approx(1.0)

    def test_single_observation_per_item(self) -> None:
        """Single observation per (item, step) → variance reported as 0.0."""
        obs = [_tp(item_id="i1", step_id="s1", run_index=0)]
        result = reproducibility_variance(obs)
        assert result["detection_variance_mean"] == pytest.approx(0.0)
        assert result["n_items_with_variance"] == pytest.approx(0.0)

    def test_empty(self) -> None:
        result = reproducibility_variance([])
        assert result["detection_variance_mean"] == pytest.approx(0.0)
        assert result["n_items_with_variance"] == pytest.approx(0.0)

    def test_multiple_items_mean(self) -> None:
        """Mean is taken across all (item, step) pairs."""
        # Group 1: constant → variance 0
        g1 = [_tp(item_id="A", step_id="x", run_index=i) for i in range(2)]
        # Group 2: alternating → variance 0.25
        g2 = [
            _obs(
                item_id="B", step_id="y", should_detect=True,
                detected=True, confidence=0.9, run_index=0,
            ),
            _obs(
                item_id="B", step_id="y", should_detect=True,
                detected=False, confidence=0.1, run_index=1,
            ),
        ]
        result = reproducibility_variance(g1 + g2)
        # Mean of (0.0, 0.25) = 0.125
        assert result["detection_variance_mean"] == pytest.approx(0.125)


# ---------------------------------------------------------------------------
# False positive rate tests
# ---------------------------------------------------------------------------


class TestFalsePositiveRate:
    def test_zero_guard_no_negatives(self) -> None:
        # All positives → FP + TN = 0, FPR = 0.0.
        obs = [_tp(), _tp(step_id="s2")]
        assert false_positive_rate(obs) == pytest.approx(0.0)

    def test_normal_case(self) -> None:
        # FP=2, TN=2 → FPR = 0.5
        obs = [_fp(), _fp(step_id="s2"), _tn(), _tn(step_id="s3")]
        assert false_positive_rate(obs) == pytest.approx(0.5)

    def test_all_tn(self) -> None:
        obs = [_tn(), _tn(step_id="s2")]
        assert false_positive_rate(obs) == pytest.approx(0.0)

    def test_empty(self) -> None:
        assert false_positive_rate([]) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Per-technique breakdown tests
# ---------------------------------------------------------------------------


class TestPerTechniqueBreakdown:
    def _technique_of(self, step_id: str) -> Optional[str]:
        mapping = {
            "step_xss": "T1059",
            "step_sqli": "T1190",
        }
        return mapping.get(step_id)

    def test_stratification(self) -> None:
        obs = [
            _tp(step_id="step_xss"),
            _fn(step_id="step_xss"),
            _tp(step_id="step_sqli"),
            _tn(step_id="step_sqli"),
        ]
        result = per_technique_breakdown(obs, self._technique_of)

        assert "T1059" in result
        assert "T1190" in result

        # T1059: TP=1, FN=1 → recall = 0.5, precision = 1.0
        t1059 = result["T1059"]
        assert t1059["n"] == 2
        assert t1059["precision"] == pytest.approx(1.0)
        assert t1059["recall"] == pytest.approx(0.5)

        # T1190: TP=1, TN=1 → precision=1.0, recall=1.0
        t1190 = result["T1190"]
        assert t1190["n"] == 2
        assert t1190["precision"] == pytest.approx(1.0)
        assert t1190["recall"] == pytest.approx(1.0)

    def test_unknown_technique_grouped(self) -> None:
        obs = [_tp(step_id="mystery_step")]
        result = per_technique_breakdown(obs, self._technique_of)
        assert "unknown" in result
        assert result["unknown"]["n"] == 1

    def test_empty_returns_empty(self) -> None:
        result = per_technique_breakdown([], self._technique_of)
        assert result == {}
