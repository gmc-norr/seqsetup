"""The login rules (security audit N-02, N-03, N-04, N-19).

A login is a row in ``web_sessions``; the browser holds a random ticket and
the row's id is the ticket's SHA-256. A ticket is accepted while:
- the row exists (logout and revocation delete it);
- it was used within the idle limit, and is younger than the hard cap;
- for a database user, the user still exists and their ``session_stamp`` is
  the one the login was made with. The stamp changes with the role or the
  password (models/local_user.py), so the account write itself revokes —
  deleting rows is cleanup.
"""

import hashlib
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping, Optional

from ..models.user import User
from ..models.web_session import WebSession

logger = logging.getLogger(__name__)

_SOURCES = ("local", "ldap")


@dataclass(frozen=True)
class SessionPolicy:
    """How long a login lasts: unused, and in all."""

    idle_seconds: int
    max_age_seconds: int

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "SessionPolicy":
        max_age = _read(environ, "SEQSETUP_SESSION_MAX_AGE_SECONDS", 28800, 300, 86400)
        idle = _read(environ, "SEQSETUP_SESSION_IDLE_SECONDS", 1800, 60, max_age)
        return cls(idle_seconds=idle, max_age_seconds=max_age)


def _read(environ, name: str, default: int, low: int, high: int) -> int:
    """An integer setting, clamped visibly. Not an integer → ValueError."""
    raw = environ.get(name)
    value = default if raw is None or raw.strip() == "" else int(raw)
    used = max(low, min(high, value))
    if used != value:
        logger.warning("%s=%s is outside %s..%s; using %s", name, value, low, high, used)
    return used


_policy: Optional[SessionPolicy] = None


def set_policy(policy: SessionPolicy) -> None:
    global _policy
    _policy = policy


def current_policy() -> SessionPolicy:
    global _policy
    if _policy is None:
        _policy = SessionPolicy.from_env()
    return _policy


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def ticket_id(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def start(sessions, user: User, now: datetime, policy: SessionPolicy) -> str:
    """Record a new login and return its ticket (for the cookie)."""
    sessions.delete_expired(
        seen_before=now - timedelta(seconds=policy.idle_seconds),
        created_before=now - timedelta(seconds=policy.max_age_seconds),
    )
    ticket = secrets.token_urlsafe(32)
    sessions.create(WebSession(
        id=ticket_id(ticket), username=user.username, display_name=user.display_name,
        email=user.email, role=user.role, source=user.source,
        session_stamp=user.session_stamp, created_at=now, last_seen_at=now,
    ))
    return ticket


def resolve(sessions, users, ticket: str, now: datetime,
            policy: SessionPolicy) -> Optional[User]:
    """The logged-in user for ``ticket``, or None. Database errors propagate."""
    sid = ticket_id(ticket)
    row = sessions.get(sid)
    if row is None:
        return None
    if (now - row.last_seen_at > timedelta(seconds=policy.idle_seconds)
            or now - row.created_at > timedelta(seconds=policy.max_age_seconds)
            or row.source not in _SOURCES):
        sessions.delete(sid)
        return None
    user = row.to_user()
    if row.source == "local":
        current = users.get_by_username(row.username)
        if current is None or current.session_stamp != row.session_stamp:
            sessions.delete(sid)
            return None
        user = current.to_user()
    sessions.touch(sid, now)
    return user


def end(sessions, ticket: str) -> None:
    sessions.delete(ticket_id(ticket))


def end_all_for(sessions, username: str) -> int:
    return sessions.delete_for_user(username)
