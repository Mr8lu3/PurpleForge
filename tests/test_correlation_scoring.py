"""Unit tests for purpleforge.correlation.scoring (heuristic confidence model)."""

from __future__ import annotations

import pytest

from purpleforge.correlation.scoring import (
    SOURCE_RELIABILITY_MAP,
    FIELD_MATCH_STRENGTH_MAP,
    ConfidenceResult,
    compute_confidence,
    compute_confidence_from_source_type,
    _resolve_source_reliability,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_WINDOW = 300.0


def _make(**overrides) -> ConfidenceResult:
    """Build a ConfidenceResult with sensible defaults, allowing per-test overrides."""
    kwargs = dict(
        temporal_delta_seconds=0.0,
        field_match_strength="exact",
        source_reliability="high",
        corroboration_count=1,
        window_seconds=_DEFAULT_WINDOW,
    )
    kwargs.update(overrides)
    return compute_confidence(**kwargs)


# ---------------------------------------------------------------------------
# Weight branches
# ---------------------------------------------------------------------------


class TestFieldMatchStrengthBranches:
    def test_exact_field_weight(self):
        r_exact = _make(field_match_strength="exact")
        r_regex = _make(field_match_strength="regex")
        assert r_exact.confidence > r_regex.confidence

    def test_regex_field_weight(self):
        r_regex = _make(field_match_strength="regex")
        r_heuristic = _make(field_match_strength="heuristic")
        assert r_regex.confidence > r_heuristic.confidence

    def test_heuristic_field_weight(self):
        r = _make(field_match_strength="heuristic")
        assert r.breakdown["field_weight"] == pytest.approx(0.5)

    def test_breakdown_field_weight_exact(self):
        r = _make(field_match_strength="exact")
        assert r.breakdown["field_weight"] == pytest.approx(1.0)

    def test_breakdown_field_weight_regex(self):
        r = _make(field_match_strength="regex")
        assert r.breakdown["field_weight"] == pytest.approx(0.75)


class TestSourceReliabilityBranches:
    def test_high_beats_medium(self):
        assert _make(source_reliability="high").confidence > _make(source_reliability="medium").confidence

    def test_medium_beats_low(self):
        assert _make(source_reliability="medium").confidence > _make(source_reliability="low").confidence

    def test_source_weight_high(self):
        assert _make(source_reliability="high").breakdown["source_weight"] == pytest.approx(1.0)

    def test_source_weight_medium(self):
        assert _make(source_reliability="medium").breakdown["source_weight"] == pytest.approx(0.75)

    def test_source_weight_low(self):
        assert _make(source_reliability="low").breakdown["source_weight"] == pytest.approx(0.5)


class TestCorroborationBranches:
    def test_count_0_means_no_bonus(self):
        # corroboration_count=0 → max(0, 0-1)=0 → bonus=0
        r = _make(corroboration_count=0)
        assert r.breakdown["corroboration_bonus"] == pytest.approx(0.0)

    def test_count_1_no_bonus(self):
        r = _make(corroboration_count=1)
        assert r.breakdown["corroboration_bonus"] == pytest.approx(0.0)

    def test_count_5_bonus(self):
        # 0.05 * (5-1) = 0.20 → min(0.2, 0.2) = 0.20
        r = _make(corroboration_count=5)
        assert r.breakdown["corroboration_bonus"] == pytest.approx(0.20)

    def test_count_20_capped(self):
        # 0.05 * (20-1) = 0.95 → capped at 0.20
        r = _make(corroboration_count=20)
        assert r.breakdown["corroboration_bonus"] == pytest.approx(0.20)

    def test_count_3_partial_bonus(self):
        # 0.05 * (3-1) = 0.10
        r = _make(corroboration_count=3)
        assert r.breakdown["corroboration_bonus"] == pytest.approx(0.10)


# ---------------------------------------------------------------------------
# Temporal decay
# ---------------------------------------------------------------------------


class TestTemporalDecay:
    def test_delta_zero_temporal_weight_one(self):
        r = _make(temporal_delta_seconds=0.0)
        assert r.breakdown["temporal_weight"] == pytest.approx(1.0)

    def test_delta_equals_window_temporal_weight_zero(self):
        r = _make(temporal_delta_seconds=_DEFAULT_WINDOW)
        assert r.breakdown["temporal_weight"] == pytest.approx(0.0)

    def test_delta_beyond_window_clamped_to_zero(self):
        r = _make(temporal_delta_seconds=_DEFAULT_WINDOW * 2)
        assert r.breakdown["temporal_weight"] == pytest.approx(0.0)

    def test_delta_half_window(self):
        r = _make(temporal_delta_seconds=_DEFAULT_WINDOW / 2)
        assert r.breakdown["temporal_weight"] == pytest.approx(0.5)

    def test_delta_quarter_window(self):
        r = _make(temporal_delta_seconds=_DEFAULT_WINDOW / 4)
        assert r.breakdown["temporal_weight"] == pytest.approx(0.75)


# ---------------------------------------------------------------------------
# Monotonicity
# ---------------------------------------------------------------------------


class TestMonotonicity:
    """Increasing any single weight dimension must not decrease confidence."""

    def test_more_corroboration_never_decreases(self):
        low = _make(corroboration_count=1)
        high = _make(corroboration_count=5)
        assert high.confidence >= low.confidence

    def test_closer_temporal_never_decreases(self):
        far = _make(temporal_delta_seconds=200.0)
        near = _make(temporal_delta_seconds=10.0)
        assert near.confidence >= far.confidence

    def test_better_field_strength_never_decreases(self):
        h = _make(field_match_strength="heuristic")
        r = _make(field_match_strength="regex")
        e = _make(field_match_strength="exact")
        assert r.confidence >= h.confidence
        assert e.confidence >= r.confidence

    def test_higher_source_reliability_never_decreases(self):
        lo = _make(source_reliability="low")
        med = _make(source_reliability="medium")
        hi = _make(source_reliability="high")
        assert med.confidence >= lo.confidence
        assert hi.confidence >= med.confidence


# ---------------------------------------------------------------------------
# Tier threshold exact values
# ---------------------------------------------------------------------------


class TestTierThresholds:
    """Verify tier assignment at boundary confidence values."""

    def _confidence_for(self, target: float) -> ConfidenceResult:
        """Find inputs that produce exactly (or very close to) *target* confidence.

        We use temporal_weight=target/0.5 keeping field=1.0(exact), source=1.0(high),
        corroboration=1 (no bonus), so: base = 0.5*tw + 0.3*1 + 0.2*1 = 0.5*tw + 0.5
        => tw = (target - 0.5) / 0.5 => delta = (1-tw)*window
        For target < 0.5 the temporal component goes to 0 and we need field/source adjustments.
        """
        raise NotImplementedError("Use parametrized inputs instead.")

    @pytest.mark.parametrize("field,source,delta,expected_tier", [
        # Tier A: exact+high+delta=0 → 0.5*1+0.3*1+0.2*1 = 1.0 → A
        ("exact", "high", 0.0, "A"),
        # Tier A: delta=120 → tw=0.6 → 0.5*0.6+0.3+0.2 = 0.80 → A (boundary)
        ("exact", "high", 120.0, "A"),
        # Tier B: delta=121 → tw=1-121/300≈0.5967 → base≈0.7983 → B
        ("exact", "high", 121.0, "B"),
        # Tier B (comfortably above 0.55): regex+low+delta=150
        # tw=1-150/300=0.5; base=0.5*0.5+0.3*0.75+0.2*0.5=0.25+0.225+0.1=0.575 → B
        ("regex", "low", 150.0, "B"),
        # Tier C: delta=200 → tw=1/3; base=0.5*(1/3)+0.3*0.75+0.2*0.5=0.167+0.225+0.1=0.492 → C
        ("regex", "low", 200.0, "C"),
        # Zero confidence scenario: worst possible inputs
        ("heuristic", "low", _DEFAULT_WINDOW * 10, "C"),
    ])
    def test_tier_assignment(self, field, source, delta, expected_tier):
        r = compute_confidence(
            temporal_delta_seconds=delta,
            field_match_strength=field,
            source_reliability=source,
            corroboration_count=1,
            window_seconds=_DEFAULT_WINDOW,
        )
        assert r.quality_tier == expected_tier, (
            f"field={field} source={source} delta={delta} "
            f"confidence={r.confidence:.4f} expected tier {expected_tier} got {r.quality_tier}"
        )

    def test_confidence_08_is_tier_a(self):
        # base = 0.5*0.6 + 0.3*1 + 0.2*1 = 0.3+0.3+0.2 = 0.80 → A
        r = compute_confidence(
            temporal_delta_seconds=120.0,
            field_match_strength="exact",
            source_reliability="high",
            corroboration_count=1,
            window_seconds=_DEFAULT_WINDOW,
        )
        assert r.confidence == pytest.approx(0.8, abs=1e-4)
        assert r.quality_tier == "A"

    def test_confidence_above_055_is_tier_b(self):
        # delta=150: tw=0.5; base=0.5*0.5+0.3*0.75+0.2*0.5=0.25+0.225+0.1=0.575 → B
        r = compute_confidence(
            temporal_delta_seconds=150.0,
            field_match_strength="regex",
            source_reliability="low",
            corroboration_count=1,
            window_seconds=_DEFAULT_WINDOW,
        )
        assert r.confidence == pytest.approx(0.575, abs=1e-4)
        assert r.quality_tier == "B"

    def test_zero_confidence_is_tier_c(self):
        # All weights zeroed: temporal beyond window, heuristic, low, no bonus
        r = compute_confidence(
            temporal_delta_seconds=9999.0,
            field_match_strength="heuristic",
            source_reliability="low",
            corroboration_count=1,
            window_seconds=_DEFAULT_WINDOW,
        )
        # base = 0.5*0 + 0.3*0.5 + 0.2*0.5 = 0.25 → C (below 0.55)
        assert r.quality_tier == "C"


# ---------------------------------------------------------------------------
# Breakdown dict completeness
# ---------------------------------------------------------------------------


class TestBreakdownDict:
    def test_all_four_keys_present(self):
        r = _make()
        expected_keys = {"temporal_weight", "field_weight", "source_weight", "corroboration_bonus"}
        assert set(r.breakdown.keys()) == expected_keys

    def test_breakdown_values_are_floats(self):
        r = _make()
        for v in r.breakdown.values():
            assert isinstance(v, float)

    def test_confidence_is_float_in_unit_interval(self):
        r = _make()
        assert isinstance(r.confidence, float)
        assert 0.0 <= r.confidence <= 1.0


# ---------------------------------------------------------------------------
# Unknown source fallback
# ---------------------------------------------------------------------------


class TestUnknownSourceFallback:
    def test_unknown_source_resolves_to_low(self):
        resolved = _resolve_source_reliability("totally_unknown_source_xyz")
        assert resolved == "low"

    def test_compute_from_source_type_unknown_uses_low(self):
        r_from_type = compute_confidence_from_source_type(
            temporal_delta_seconds=0.0,
            field_match_strength="exact",
            source_type="unknown_src",
            corroboration_count=1,
            window_seconds=_DEFAULT_WINDOW,
        )
        r_explicit_low = compute_confidence(
            temporal_delta_seconds=0.0,
            field_match_strength="exact",
            source_reliability="low",
            corroboration_count=1,
            window_seconds=_DEFAULT_WINDOW,
        )
        assert r_from_type.confidence == pytest.approx(r_explicit_low.confidence)

    def test_known_source_web_requests_is_high(self):
        assert SOURCE_RELIABILITY_MAP["web_requests"] == "high"

    def test_known_source_csv_is_low(self):
        assert SOURCE_RELIABILITY_MAP["csv"] == "low"

    def test_known_source_sysmon_is_medium(self):
        assert SOURCE_RELIABILITY_MAP["sysmon"] == "medium"
