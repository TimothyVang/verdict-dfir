"""Wilson 95% confidence intervals on the accuracy recall/precision rates.

The point of Wilson over the naive normal approximation is that it stays inside
[0, 100] and behaves at small n / extreme rates — exactly the regime a golden
corpus lives in (7/7, 0/5, 7/14 on a single image).
"""

from __future__ import annotations

from findevil_agent.accuracy import _wilson_ci


def _approx(a: float, b: float, tol: float = 0.2) -> bool:
    return abs(a - b) <= tol


class TestWilsonCI:
    def test_half_of_fourteen(self) -> None:
        lo, hi = _wilson_ci(7, 14)
        assert _approx(lo, 26.8)
        assert _approx(hi, 73.2)
        assert lo < 50 < hi  # 50% point estimate sits inside its band

    def test_perfect_rate_upper_clamps_at_100(self) -> None:
        # Normal approximation would run past 100; Wilson must not.
        lo, hi = _wilson_ci(7, 7)
        assert hi == 100.0
        assert _approx(lo, 64.6)

    def test_zero_rate_lower_clamps_at_0(self) -> None:
        lo, hi = _wilson_ci(0, 5)
        assert lo == 0.0
        assert _approx(hi, 43.4)

    def test_no_trials_returns_none(self) -> None:
        assert _wilson_ci(0, 0) is None
        assert _wilson_ci(5, 0) is None

    def test_bounds_ordered_and_contain_point_estimate(self) -> None:
        for k, n in [(1, 3), (9, 10), (14, 14), (3, 100), (50, 100)]:
            lo, hi = _wilson_ci(k, n)
            assert 0.0 <= lo <= hi <= 100.0
            point = k / n * 100
            assert lo <= point <= hi

    def test_tighter_band_with_more_samples(self) -> None:
        # Same 50% rate, 10x the sample -> narrower interval.
        narrow = _wilson_ci(70, 140)
        wide = _wilson_ci(7, 14)
        assert (narrow[1] - narrow[0]) < (wide[1] - wide[0])
