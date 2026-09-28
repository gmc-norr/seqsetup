"""Kept copies of deleted runs (spec 2026-09-28 group 2a, F16).

Insert and move-forward only: ``start`` inserts a pending copy, and
``mark_completed`` / ``mark_abandoned`` move a pending copy once. There is
no delete and no replace, so nothing in the app can remove or overwrite a
copy. (Someone with direct access to the database could; that is out of
scope, as for the audit trail.)
"""

from datetime import datetime
from typing import Optional

from pymongo.database import Database

from ..models.deleted_run import ABANDONED, COMPLETED, PENDING, DeletedRun

_SUMMARY = {
    "copy_id": 1, "run_id": 1, "state": 1, "run_name": 1, "status": 1,
    "sample_count": 1, "created_by": 1, "deleted_by": 1,
    "started_at": 1, "finished_at": 1, "run_version": 1,
}


class DeletedRunRepository:
    """Manages the ``deleted_runs`` collection."""

    COLLECTION = "deleted_runs"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]
        self.collection.create_index([("run_id", 1), ("state", 1)])
        self.collection.create_index([("started_at", -1)])

    def start(self, copy: DeletedRun) -> None:
        """Insert a pending copy. A clash on the id raises; nothing is replaced."""
        if copy.state != PENDING:
            raise ValueError("A copy must start pending")
        self.collection.insert_one(copy.to_dict())

    def _finish(self, copy_id: str, state: str, at: datetime, reason: str = "") -> bool:
        result = self.collection.update_one(
            {"_id": copy_id, "state": PENDING},
            {"$set": {"state": state, "finished_at": at.isoformat(), "abandon_reason": reason}},
        )
        return result.modified_count == 1

    def mark_completed(self, copy_id: str, at: datetime) -> bool:
        """Pending -> completed. False if the copy was not pending."""
        return self._finish(copy_id, COMPLETED, at)

    def mark_abandoned(self, copy_id: str, at: datetime, reason: str) -> bool:
        """Pending -> abandoned. False if the copy was not pending."""
        return self._finish(copy_id, ABANDONED, at, reason)

    def list_for_page(self) -> list[dict]:
        """Summaries (no snapshot) of every completed or pending copy, newest first."""
        cursor = self.collection.find(
            {"state": {"$in": [COMPLETED, PENDING]}}, _SUMMARY,
        ).sort([("started_at", -1), ("_id", -1)])
        return list(cursor)

    def get(self, copy_id: str) -> Optional[DeletedRun]:
        doc = self.collection.find_one({"_id": copy_id})
        return DeletedRun.from_dict(doc) if doc else None

    def list_for_run(self, run_id: str) -> list[dict]:
        """Summaries of one run's completed or pending copies, read now."""
        return list(self.collection.find(
            {"run_id": run_id, "state": {"$in": [COMPLETED, PENDING]}}, _SUMMARY,
        ))
