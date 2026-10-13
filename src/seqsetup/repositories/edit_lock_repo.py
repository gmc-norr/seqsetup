"""The edit locks, one per run. Thin: who may take one and when it counts
as free live in ``services/edit_locks.py``."""

from datetime import datetime
from typing import Optional

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from ..models.edit_lock import EditLock


class EditLockRepository:
    """Manages the ``edit_locks`` collection."""

    COLLECTION = "edit_locks"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]

    def get(self, run_id: str) -> Optional[EditLock]:
        doc = self.collection.find_one({"_id": run_id})
        return EditLock.from_dict(doc) if doc else None

    def take(self, lock: EditLock, *, others_seen_before: datetime) -> bool:
        """Store ``lock`` unless another user's lock was seen at or after
        ``others_seen_before``. A lock already held by the same user keeps
        its start time. Each write is atomic and checks its own condition:
        True when the lock is now ours."""
        mine = self.collection.update_one(
            {"_id": lock.run_id, "username": lock.username},
            {"$set": {"display_name": lock.display_name}, "$max": {"seen_at": lock.seen_at}})
        if mine.matched_count == 1:
            return True
        try:
            self.collection.update_one(
                {"_id": lock.run_id, "seen_at": {"$lt": others_seen_before}},
                {"$set": {k: v for k, v in lock.to_dict().items() if k != "_id"}},
                upsert=True,
            )
        except DuplicateKeyError:
            return False
        return True

    def replace(self, lock: EditLock) -> None:
        """Store ``lock`` whoever held the run before."""
        self.collection.replace_one({"_id": lock.run_id}, lock.to_dict(), upsert=True)

    def touch(self, run_id: str, username: str, when: datetime) -> bool:
        """Move seen_at forward to ``when`` if ``username`` holds the run."""
        result = self.collection.update_one(
            {"_id": run_id, "username": username}, {"$max": {"seen_at": when}})
        return result.matched_count == 1

    def delete(self, run_id: str, username: Optional[str] = None) -> bool:
        """Remove the run's lock; with ``username``, only when they hold it."""
        query = {"_id": run_id} if username is None else {"_id": run_id, "username": username}
        return self.collection.delete_one(query).deleted_count == 1
