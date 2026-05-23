"""In-process rate limiter for login and API bearer endpoints.

A sliding-window counter keyed by (bucket, identity). When the count
within ``window_seconds`` exceeds ``max_requests``, requests are refused.
Thread-safe via a single lock.

This is in-process — multi-replica deployments should also configure a
reverse-proxy rate limit (nginx ``limit_req``, Caddy ``rate_limit``, etc.)
because each replica tracks its own counters. The in-process limiter
catches the common single-host case and credential-stuffing scenarios.

Tunables (env vars):
  - SEQSETUP_LOGIN_RATE_LIMIT     default "20" (attempts)
  - SEQSETUP_LOGIN_RATE_WINDOW    default "60" (seconds)
  - SEQSETUP_API_RATE_LIMIT       default "100"
  - SEQSETUP_API_RATE_WINDOW      default "60"
"""

import logging
import os
import threading
import time
from collections import deque
from typing import Optional


logger = logging.getLogger(__name__)


class RateLimiter:
    """Sliding-window in-memory counter."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max(1, int(max_requests))
        self.window_seconds = max(1, int(window_seconds))
        self._buckets: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, identity: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds). retry_after is 0 on allow."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            timestamps = self._buckets.setdefault(identity, deque())
            # Drop expired entries from the head.
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()
            if len(timestamps) >= self.max_requests:
                # Retry-after: when the oldest entry will fall off the window.
                retry = int(timestamps[0] + self.window_seconds - now) + 1
                return False, max(1, retry)
            timestamps.append(now)
            return True, 0

    def reset(self) -> None:
        """Clear all state (for tests)."""
        with self._lock:
            self._buckets.clear()


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


# Module-level limiters, lazily constructed so the env vars are read at first use.
_login_limiter: Optional[RateLimiter] = None
_api_limiter: Optional[RateLimiter] = None


def get_login_limiter() -> RateLimiter:
    global _login_limiter
    if _login_limiter is None:
        _login_limiter = RateLimiter(
            max_requests=_int_env("SEQSETUP_LOGIN_RATE_LIMIT", 20),
            window_seconds=_int_env("SEQSETUP_LOGIN_RATE_WINDOW", 60),
        )
    return _login_limiter


def get_api_limiter() -> RateLimiter:
    global _api_limiter
    if _api_limiter is None:
        _api_limiter = RateLimiter(
            max_requests=_int_env("SEQSETUP_API_RATE_LIMIT", 100),
            window_seconds=_int_env("SEQSETUP_API_RATE_WINDOW", 60),
        )
    return _api_limiter


def reset_all_limiters() -> None:
    """Test helper — wipe state so a previous test's traffic doesn't leak in."""
    global _login_limiter, _api_limiter
    if _login_limiter is not None:
        _login_limiter.reset()
    if _api_limiter is not None:
        _api_limiter.reset()


def client_identity(req) -> str:
    """Extract a client identity for rate-limit bucketing.

    Defaults to the direct TCP client (``req.client.host``) because clients
    can forge the ``X-Forwarded-For`` header to defeat per-IP limits. Only
    when ``SEQSETUP_TRUST_FORWARDED_FOR=1`` (set when the app sits behind a
    trusted reverse proxy that overwrites the header) do we honor the first
    XFF hop. This protects login + API limits from anonymous spoofing in
    direct-exposed deployments.
    """
    trust_xff = os.environ.get("SEQSETUP_TRUST_FORWARDED_FOR", "").lower() in ("1", "true", "yes")
    if trust_xff:
        xff = req.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",", 1)[0].strip()
    client = getattr(req, "client", None)
    if client and getattr(client, "host", None):
        return client.host
    return "unknown"
