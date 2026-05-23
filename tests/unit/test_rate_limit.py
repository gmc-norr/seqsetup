"""Tests for the in-process rate limiter."""

import time

import pytest

from seqsetup.rate_limit import RateLimiter


class TestRateLimiterCore:
    def test_allows_under_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            ok, _ = limiter.allow("alice")
            assert ok is True

    def test_blocks_over_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.allow("alice")
        ok, retry = limiter.allow("alice")
        assert ok is False
        assert retry > 0

    def test_separate_identities_have_independent_budgets(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.allow("alice")
        limiter.allow("alice")
        ok_alice, _ = limiter.allow("alice")
        assert ok_alice is False
        ok_bob, _ = limiter.allow("bob")
        assert ok_bob is True

    def test_window_expiry_releases_budget(self, monkeypatch):
        # Simulate the monotonic clock advancing past the window.
        fake_now = [1000.0]
        import seqsetup.rate_limit as rl
        monkeypatch.setattr(rl.time, "monotonic", lambda: fake_now[0])

        limiter = RateLimiter(max_requests=2, window_seconds=10)
        limiter.allow("alice")
        limiter.allow("alice")
        ok, _ = limiter.allow("alice")
        assert ok is False

        # Advance past the window.
        fake_now[0] += 11
        ok, _ = limiter.allow("alice")
        assert ok is True

    def test_min_max_requests_one(self):
        """max_requests=0 should be clamped to 1, not 'block everything'."""
        limiter = RateLimiter(max_requests=0, window_seconds=60)
        ok, _ = limiter.allow("x")
        assert ok is True
