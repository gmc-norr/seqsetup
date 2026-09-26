"""One login in the server-side login list (``web_sessions``).

The browser's cookie holds only a random ticket; this row holds the SHA-256
of that ticket as its id, so a copy of the database cannot be turned back
into working cookies. Times are naive UTC.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .user import User, UserRole

TEXT_CAP = 256
_TEXT_FIELDS = ("username", "display_name", "email")


def as_utc(value: datetime) -> datetime:
    """Naive UTC. An aware value is converted; a naive one is taken as UTC."""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


@dataclass
class WebSession:
    """One login."""

    id: str
    username: str
    display_name: str
    role: UserRole
    source: str
    session_stamp: str
    created_at: datetime
    last_seen_at: datetime
    email: Optional[str] = None

    def __setattr__(self, name, value):
        if name in _TEXT_FIELDS and value is not None:
            value = str(value)[:TEXT_CAP]
        elif name in ("created_at", "last_seen_at"):
            value = as_utc(value)
        object.__setattr__(self, name, value)

    def to_user(self) -> User:
        return User(username=self.username, display_name=self.display_name,
                    role=self.role, email=self.email, source=self.source,
                    session_stamp=self.session_stamp)

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "username": self.username,
            "display_name": self.display_name,
            "email": self.email,
            "role": self.role.value,
            "source": self.source,
            "session_stamp": self.session_stamp,
            "created_at": self.created_at,
            "last_seen_at": self.last_seen_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WebSession":
        return cls(
            id=data["_id"],
            username=data.get("username", ""),
            display_name=data.get("display_name", ""),
            email=data.get("email"),
            role=UserRole(data.get("role", "standard")),
            source=data.get("source", ""),
            session_stamp=data.get("session_stamp", ""),
            created_at=data["created_at"],
            last_seen_at=data["last_seen_at"],
        )
