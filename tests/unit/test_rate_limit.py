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


class TestBucketsAreNotKeptForever:
    """A bucket whose window has passed is dropped.

    Nothing ever removed a key, so a caller that kept naming new
    identities grew the dict by one key per request until the process was
    restarted (security review 2026-10).
    """

    @staticmethod
    def _frozen(monkeypatch):
        """A monotonic clock the test moves by hand. Returns the list holding
        the current reading, so `clock[0] += 11` advances it."""
        import seqsetup.rate_limit as rl
        clock = [1000.0]
        monkeypatch.setattr(rl.time, "monotonic", lambda: clock[0])
        return clock

    def test_a_key_whose_window_has_passed_is_dropped(self, monkeypatch):
        clock = self._frozen(monkeypatch)
        limiter = RateLimiter(max_requests=2, window_seconds=10)
        limiter.allow("alice")

        clock[0] += 11
        limiter.allow("bob")

        assert "alice" not in limiter._buckets

    def test_a_key_still_inside_its_window_is_kept(self, monkeypatch):
        """Alice's last attempt was at T+6, so when bob's at T+12 drops the
        dead keys hers is six seconds inside the ten-second window."""
        clock = self._frozen(monkeypatch)
        limiter = RateLimiter(max_requests=2, window_seconds=10)
        limiter.allow("alice")
        clock[0] += 6
        limiter.allow("alice")

        clock[0] += 6
        limiter.allow("bob")

        assert "alice" in limiter._buckets

    def test_dropping_dead_keys_does_not_hand_budget_back_early(self, monkeypatch):
        """A bucket with one live timestamp keeps it: alice spent one of her
        two attempts at T+6, so at T+12 she has one left, not two."""
        clock = self._frozen(monkeypatch)
        limiter = RateLimiter(max_requests=2, window_seconds=10)
        limiter.allow("alice")
        clock[0] += 6
        limiter.allow("alice")

        clock[0] += 6
        assert limiter.allow("alice") == (True, 0)
        ok, retry = limiter.allow("alice")
        assert ok is False
        assert retry > 0

    def test_the_count_stays_bounded_when_every_request_names_a_new_identity(
            self, monkeypatch):
        clock = self._frozen(monkeypatch)
        limiter = RateLimiter(max_requests=2, window_seconds=10)

        for n in range(500):
            limiter.allow(f"name-{n}")
            clock[0] += 1

        assert len(limiter._buckets) <= 25, (
            f"{len(limiter._buckets)} buckets held after 500 requests "
            f"spread over 500 seconds of a 10-second window"
        )


class TestRetryAfterReadsWithoutCounting:
    """``retry_after`` answers what ``allow`` would have reported, without
    counting the request or creating a bucket — so the login handler can
    keep the ``Retry-After`` header it has always sent for a request the
    per-address cap already refused."""

    def test_an_unknown_identity_waits_for_nothing(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        assert limiter.retry_after("nobody") == 0

    def test_it_creates_no_bucket(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        limiter.retry_after("nobody")

        assert limiter._buckets == {}

    def test_an_identity_under_its_cap_waits_for_nothing(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.allow("alice")

        assert limiter.retry_after("alice") == 0

    def test_a_full_bucket_reports_what_allow_reports(self, monkeypatch):
        import seqsetup.rate_limit as rl
        monkeypatch.setattr(rl.time, "monotonic", lambda: 1000.0)
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.allow("alice")
        limiter.allow("alice")

        peeked = limiter.retry_after("alice")

        assert peeked == limiter.allow("alice")[1]
        assert peeked == 61

    def test_it_spends_none_of_the_budget(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        for _ in range(5):
            limiter.retry_after("alice")

        assert limiter.allow("alice")[0] is True
        assert limiter.allow("alice")[0] is True
        assert limiter.allow("alice")[0] is False
