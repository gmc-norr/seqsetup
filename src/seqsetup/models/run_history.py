"""Append-only per-run change-history entry.

Records who changed what on a run and when. Produced by services.run_history
from the diff in services.run_diff; persisted by RunHistoryRepository
(insert-only). Not user-input-facing — values come from the diff engine and
run metadata, so this model is a plain serializable record.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


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
        """Keyset-pagination cursor: (timestamp_iso, id)."""
        return (self.timestamp.isoformat(), self.id)

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "id": self.id,
            "run_id": self.run_id,
            "timestamp": self.timestamp.isoformat(),
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
