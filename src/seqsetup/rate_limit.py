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
from typing import NamedTuple, Optional


logger = logging.getLogger(__name__)


class RateLimiter:
    """Sliding-window in-memory counter."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max(1, int(max_requests))
        self.window_seconds = max(1, int(window_seconds))
        self._buckets: dict[str, deque] = {}
        self._swept_at = time.monotonic()
        self._lock = threading.Lock()

    def _sweep(self, now: float, cutoff: float) -> None:
        """Drop every bucket with no timestamp left inside the window.

        Called under the lock and at most once per window, so the dict can
        hold only the keys the traffic of a window created (and those the
        window before it created that this sweep has not reached yet).
        Nothing used to remove a key, so a caller naming a new identity on
        every request grew the dict by one key per request for as long as
        the process lived.
        """
        if now - self._swept_at < self.window_seconds:
            return
        self._swept_at = now
        for key in [k for k, stamps in self._buckets.items()
                    if not stamps or stamps[-1] < cutoff]:
            del self._buckets[key]

    def retry_after(self, identity: str) -> int:
        """What ``allow`` would report as retry_after for ``identity``,
        without counting the request or creating a bucket.

        ``allow`` reports 0 for anything it lets through, an identity it has
        never seen included, so an unknown identity is 0 here too. A caller
        that has already refused a request can read the wait this identity
        would have been given without letting that refused request name a
        bucket into existence.
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            live = [t for t in self._buckets.get(identity, ()) if t >= cutoff]
            if len(live) < self.max_requests:
                return 0
            return max(1, int(live[0] + self.window_seconds - now) + 1)

    def allow(self, identity: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds). retry_after is 0 on allow."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            self._sweep(now, cutoff)
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
            self._swept_at = time.monotonic()


class Refusals(NamedTuple):
    """What one audit row must account for, as ``count_refusal`` reports it.

    ``total`` is every refusal the row stands for, and ``earlier`` how many
    of those were refused in earlier windows of the same identity. Only the
    row's own refusal was typed with the name that goes on the row; the
    carried part belongs to the address, and may have been typed with other
    names, so the two are reported apart (and written apart) rather than
    crediting one named account with all of them. ``total`` of 0 means no
    row.
    """

    total: int
    earlier: int


class RefusedRequestCounter:
    """How many refusals one identity's next audit row should account for.

    Every refused request used to write its own ``login.rate_limited``
    row, so a flood of a few thousand buried every other event on
    Admin > Audit under a few thousand rows that all said the same thing.
    At most one row per identity per window is written now, and it carries
    the count.

    The audit trail is insert-only -- nothing in SeqSetup changes a row
    that has been written -- so a row cannot be updated with a count that
    grows after it went out. Instead the first refusal of an identity's
    window asks for a row at once, the refusals that follow are counted,
    and their count is carried by that identity's next row: the first
    refusal of a later window. Every refusal is therefore accounted for in
    exactly one row.

    A count still owed when the process stops is lost, and so is one whose
    identity does not come back within _OWED_RETENTION_WINDOWS: a row's
    count is therefore at least that many refusals, not exactly that many.
    Both are the known limits of counting in the process, stated in
    docs/admin-guide/audit-trail.rst.
    """

    # How many windows an identity that still owes a count is kept for. One
    # that owes nothing is forgotten after a single window; one that owes
    # is given a few more, because its count has nowhere to go but its next
    # row. Keeping it until that row came grew the dict by one key per
    # identity for the life of the process -- and with the first
    # X-Forwarded-For hop as the identity, those keys are the client's to
    # choose. An identity that has not been refused again for three whole
    # windows will probably never come back, and its count then has nowhere
    # to go at all.
    _OWED_RETENTION_WINDOWS = 3

    def __init__(self, window_seconds: int):
        self.window_seconds = max(1, int(window_seconds))
        # identity -> (when its current window started, refusals owed)
        self._windows: dict[str, tuple[float, int]] = {}
        self._swept_at = time.monotonic()
        self._lock = threading.Lock()

    def _sweep(self, now: float) -> None:
        """Forget identities whose window has passed: after one window when
        they owe nothing, after _OWED_RETENTION_WINDOWS when they owe a
        count.

        Called under the lock and at most once per window, like
        ``RateLimiter._sweep``: without it a flood from many addresses adds
        a key per address and gives none back. An identity that owes was
        kept for good, so the addresses of a flood that never came back
        stayed for the life of the process; forgetting one loses its count,
        which is the known limit above.
        """
        if now - self._swept_at < self.window_seconds:
            return
        self._swept_at = now
        owed_kept_for = self.window_seconds * self._OWED_RETENTION_WINDOWS
        for identity in [key for key, (started, owed) in self._windows.items()
                         if now - started >= (owed_kept_for if owed
                                              else self.window_seconds)]:
            del self._windows[identity]

    def count_refusal(self, identity: str) -> Refusals:
        """Record one refusal; return what a row must carry, or zeros for none.

        The first refusal of an identity's window asks for a row that
        accounts for itself plus whatever that identity still owed from a
        window that has passed; ``Refusals.earlier`` is that owed part, so
        the row can say how much of its count was refused before this
        window and under whatever names came then.
        """
        now = time.monotonic()
        with self._lock:
            self._sweep(now)
            started, owed = self._windows.get(identity, (None, 0))
            if started is None or now - started >= self.window_seconds:
                self._windows[identity] = (now, 0)
                return Refusals(1 + owed, owed)
            self._windows[identity] = (started, owed + 1)
            return Refusals(0, 0)

    def reset(self) -> None:
        """Clear all state (for tests)."""
        with self._lock:
            self._windows.clear()
            self._swept_at = time.monotonic()


_login_refusal_counter: Optional[RefusedRequestCounter] = None


def get_login_refusal_counter() -> "RefusedRequestCounter":
    """The shared counter for refused sign-ins, on the login limiter's window."""
    global _login_refusal_counter
    if _login_refusal_counter is None:
        _login_refusal_counter = RefusedRequestCounter(get_login_limiter().window_seconds)
    return _login_refusal_counter


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
    if _login_refusal_counter is not None:
        _login_refusal_counter.reset()


def client_identity(req) -> str:
    """Extract a client identity for rate-limit bucketing.

    Defaults to the direct TCP client (``req.client.host``) because clients
    can forge the ``X-Forwarded-For`` header to defeat per-IP limits. Only
    when ``SEQSETUP_TRUST_FORWARDED_FOR=1`` (set when the app sits behind a
    trusted reverse proxy that overwrites the header) do we honor the first
    XFF hop. This protects login + API limits from anonymous spoofing in
    direct-exposed deployments.

    The first hop is the real client only while the proxy REPLACES the
    header. The deployment recipe does that (``$remote_addr``, not
    ``$proxy_add_x_forwarded_for``) and sets this variable to 1, so each
    user behind the proxy has their own sign-in limit instead of every user
    sharing the proxy's address. See docs/getting-started/deployment.rst,
    Reverse Proxy Configuration.
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
