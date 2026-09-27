"""The server-side login list. Thin: no expiry or revocation rules here —
those live in ``services/web_sessions.py``."""

from datetime import datetime
from typing import Optional

from pymongo.database import Database

from ..models.web_session import WebSession


class WebSessionRepository:
    """Manages the ``web_sessions`` collection."""

    COLLECTION = "web_sessions"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]
        self.collection.create_index("username")
        self.collection.create_index("last_seen_at")
        self.collection.create_index("created_at")

    def create(self, ws: WebSession) -> None:
        self.collection.insert_one(ws.to_dict())

    def get(self, session_id: str) -> Optional[WebSession]:
        doc = self.collection.find_one({"_id": session_id})
        return WebSession.from_dict(doc) if doc else None

    def touch(self, session_id: str, when: datetime) -> None:
        """Move last_seen_at forward to ``when`` (never backwards)."""
        self.collection.update_one({"_id": session_id}, {"$max": {"last_seen_at": when}})

    def delete(self, session_id: str) -> None:
        self.collection.delete_one({"_id": session_id})

    def delete_for_user(self, username: str) -> int:
        return self.collection.delete_many({"username": username}).deleted_count

    def delete_expired(self, *, seen_before: datetime, created_before: datetime) -> int:
        return self.collection.delete_many({"$or": [
            {"last_seen_at": {"$lt": seen_before}},
            {"created_at": {"$lt": created_before}},
        ]}).deleted_count
