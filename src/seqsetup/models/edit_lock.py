"""Who is editing a Draft run (the user's decision, 2026-10-13).

One row in ``edit_locks`` per run, with the run's id as its id. Times are
naive UTC. The rules -- who may take it, when it counts as free -- live in
``services/edit_locks.py``.
"""

from dataclasses import dataclass
from datetime import datetime

from .web_session import as_utc

TEXT_CAP = 256
_TEXT_FIELDS = ("username", "display_name")


@dataclass
class EditLock:
    """The person editing one run."""

    run_id: str
    username: str
    display_name: str
    started_at: datetime
    seen_at: datetime

    def __setattr__(self, name, value):
        if name in _TEXT_FIELDS and value is not None:
            value = str(value)[:TEXT_CAP]
        elif name in ("started_at", "seen_at"):
            value = as_utc(value)
        object.__setattr__(self, name, value)

    def to_dict(self) -> dict:
        return {
            "_id": self.run_id,
            "username": self.username,
            "display_name": self.display_name,
            "started_at": self.started_at,
            "seen_at": self.seen_at,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "EditLock":
        return cls(
            run_id=doc["_id"],
            username=doc["username"],
            display_name=doc.get("display_name") or doc["username"],
            started_at=doc["started_at"],
            seen_at=doc["seen_at"],
        )
