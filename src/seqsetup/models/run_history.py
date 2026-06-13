"""Append-only per-run change-history entry.

Records who changed what on a run and when. Produced by services.run_history
from the diff in services.run_diff; persisted by RunHistoryRepository
(insert-only). Not user-input-facing — values come from the diff engine and
run metadata, so this model is a plain serializable record.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _canonical_ts(ts: datetime) -> str:
    """Single canonical, offset-free timestamp string for keyset pagination.

    Pagination compares these strings lexically and relies on lexical order
    matching chronological order. The one thing that breaks that is a timezone
    offset suffix (a ``+02:00`` value sorts as ``...:00+02:00`` and collates
    wrong against a UTC value), so tz-aware timestamps are coerced to UTC-naive.
    For naive values ``isoformat()`` is already lexically chronological — its
    only variable part is a trailing fractional-second suffix, and a missing
    suffix is a prefix of any present one, so order is preserved. We keep
    ``isoformat()`` (rather than a fixed-width ``%f``) precisely so the output
    is byte-identical to history rows written before this normalization
    existed — there is no migration boundary in the cursor."""
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.isoformat()


@dataclass
class RunHistoryEntry:
    """One change-history record for a run."""

    run_id: str
    timestamp: datetime
    actor: str
    kind: str  # "created" | "updated"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    provenance: Optional[dict] = None  # created: {"source": ..., "ref": ...}
    field_changes: list = field(default_factory=list)   # [{field, before, after}]
    sample_changes: list = field(default_factory=list)  # [{sample_id, kind, fields}]

    def cursor(self) -> tuple:
        """Keyset-pagination cursor: (canonical_timestamp, id). Must match the
        persisted ``timestamp`` exactly so the ``$lt`` page boundary is sound."""
        return (_canonical_ts(self.timestamp), self.id)

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "id": self.id,
            "run_id": self.run_id,
            "timestamp": _canonical_ts(self.timestamp),
            "actor": self.actor,
            "kind": self.kind,
            "provenance": self.provenance,
            "field_changes": self.field_changes,
            "sample_changes": self.sample_changes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RunHistoryEntry":
        ts = data["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return cls(
            id=data.get("_id") or data["id"],
            run_id=data["run_id"],
            timestamp=ts,
            actor=data.get("actor", ""),
            kind=data.get("kind", "updated"),
            provenance=data.get("provenance"),
            field_changes=data.get("field_changes", []),
            sample_changes=data.get("sample_changes", []),
        )
