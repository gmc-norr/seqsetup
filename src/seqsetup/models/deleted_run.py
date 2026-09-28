"""A kept copy of a deleted run (spec 2026-09-28 group 2a, F16).

Each delete attempt writes its own copy before the run is deleted. The copy
starts ``pending`` and moves once: to ``completed`` (the run was deleted) or
``abandoned`` (it was not). Nothing in the app removes or overwrites a copy.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .sequencing_run import SequencingRun

PENDING = "pending"
COMPLETED = "completed"
ABANDONED = "abandoned"
_STATES = (PENDING, COMPLETED, ABANDONED)


@dataclass
class DeletedRun:
    """One kept copy: a summary for the list page, plus the whole run."""

    run_id: str
    run_name: str
    status: str
    sample_count: int
    created_by: str
    deleted_by: str
    started_at: datetime
    run_version: str
    run: dict
    copy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: str = PENDING
    finished_at: Optional[datetime] = None
    abandon_reason: str = ""

    def __setattr__(self, name, value):
        if name in ("run_name", "created_by", "deleted_by") and isinstance(value, str):
            value = value[:256]
        elif name == "state" and value not in _STATES:
            raise ValueError(f"Unknown copy state {value!r}")
        object.__setattr__(self, name, value)

    @classmethod
    def of(cls, run: SequencingRun, deleted_by: str, at: datetime) -> "DeletedRun":
        """A pending copy of ``run`` exactly as it was checked."""
        return cls(
            run_id=run.id,
            run_name=run.run_name,
            status=run.status.value,
            sample_count=len(run.samples),
            created_by=run.created_by,
            deleted_by=deleted_by,
            started_at=at,
            run_version=run.updated_at.isoformat(),
            run=run.to_dict(),
        )

    def to_dict(self) -> dict:
        return {
            "_id": self.copy_id,
            "copy_id": self.copy_id,
            "run_id": self.run_id,
            "state": self.state,
            "run_name": self.run_name,
            "status": self.status,
            "sample_count": self.sample_count,
            "created_by": self.created_by,
            "deleted_by": self.deleted_by,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "abandon_reason": self.abandon_reason,
            "run_version": self.run_version,
            "run": self.run,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeletedRun":
        finished = data.get("finished_at")
        return cls(
            copy_id=data.get("_id") or data["copy_id"],
            run_id=data["run_id"],
            state=data.get("state", PENDING),
            run_name=data.get("run_name", ""),
            status=data.get("status", ""),
            sample_count=data.get("sample_count", 0),
            created_by=data.get("created_by", ""),
            deleted_by=data.get("deleted_by", ""),
            started_at=datetime.fromisoformat(data["started_at"]),
            finished_at=datetime.fromisoformat(finished) if finished else None,
            abandon_reason=data.get("abandon_reason", ""),
            run_version=data.get("run_version", ""),
            run=data.get("run", {}),
        )
