"""Insert-only repository for run change-history entries.

Application-level append-only: it exposes `append` (insert_one) and read/delete,
but NO update/upsert path — `RunHistoryEntry` documents are never rewritten
through the app. This is not cryptographic tamper-evidence (a DB admin can edit
the collection); that is out of scope.
"""

from typing import Optional

from pymongo.database import Database

from ..models.run_history import RunHistoryEntry


class RunHistoryRepository:
    """Manages the `run_history` collection. Insert-only by API surface."""

    COLLECTION = "run_history"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]
        self.collection.create_index([("run_id", 1), ("timestamp", -1)])

    def append(self, entry: RunHistoryEntry) -> None:
        """Insert a new entry. Raises DuplicateKeyError on a colliding _id."""
        self.collection.insert_one(entry.to_dict())

    def list_by_run(
        self,
        run_id: str,
        *,
        limit: int,
        before_ts: Optional[str] = None,
        before_id: Optional[str] = None,
    ) -> list[RunHistoryEntry]:
        """Newest-first, bounded by `limit`. Keyset-paginate older with the
        (before_ts, before_id) cursor from a prior page's last entry."""
        flt: dict = {"run_id": run_id}
        if before_ts is not None and before_id is not None:
            flt["$or"] = [
                {"timestamp": {"$lt": before_ts}},
                {"timestamp": before_ts, "_id": {"$lt": before_id}},
            ]
        cur = (
            self.collection.find(flt)
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(limit)
        )
        return [RunHistoryEntry.from_dict(doc) for doc in cur]

    def delete_by_run(self, run_id: str) -> int:
        """Delete all history for a run (cascade). Returns count deleted."""
        return self.collection.delete_many({"run_id": run_id}).deleted_count
