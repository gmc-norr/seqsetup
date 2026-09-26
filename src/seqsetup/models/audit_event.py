"""One audit-trail event: who did what, to what, when, and how it ended.

Built by ``services.audit_log.audit()`` for every audit call and kept by
``AuditEventRepository`` (insert-only). Web-address secrets are already
removed by ``audit()``; this model bounds sizes so one event can never grow
large, on construction and on every later assignment.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

import bson

from .run_history import _canonical_ts

# Longest stored value per text field. The /admin/audit search boxes use the
# same limits, so any stored value can be searched for.
FIELD_CAPS = {"event": 128, "actor": 256, "target": 1024, "outcome": 32}

# Details bigger than this (BSON-encoded) are replaced by a marker.
MAX_DETAILS_BYTES = 64 * 1024


def _bounded_details(value) -> dict:
    if not value:
        return {}
    if not isinstance(value, dict):
        return {"details_omitted": True, "reason": "not a dict"}
    try:
        size = len(bson.encode({"details": value}))
    except Exception:
        return {"details_omitted": True, "reason": "not storable"}
    if size > MAX_DETAILS_BYTES:
        return {"details_omitted": True, "bytes": size}
    return value


@dataclass
class AuditEvent:
    """One audit-trail record."""

    timestamp: datetime
    event: str
    actor: str = ""
    target: str = ""
    outcome: str = "success"
    details: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __setattr__(self, name, value):
        if name in FIELD_CAPS:
            value = ("" if value is None else str(value))[:FIELD_CAPS[name]]
        elif name == "details":
            value = _bounded_details(value)
        object.__setattr__(self, name, value)

    def cursor(self) -> tuple:
        """Keyset-pagination cursor: (canonical timestamp, id)."""
        return (_canonical_ts(self.timestamp), self.id)

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "id": self.id,
            "timestamp": _canonical_ts(self.timestamp),
            "event": self.event,
            "actor": self.actor,
            "target": self.target,
            "outcome": self.outcome,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        ts = data["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return cls(
            id=data.get("_id") or data["id"],
            timestamp=ts,
            event=data.get("event", ""),
            actor=data.get("actor", ""),
            target=data.get("target", ""),
            outcome=data.get("outcome", ""),
            details=data.get("details") or {},
        )
