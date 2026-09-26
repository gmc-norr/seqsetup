"""Insert-only repository for the audit trail.

Exposes ``append`` and ``search`` only — no update, replace or delete — so no
code path in the app can change or remove an audit event. This is not
tamper-evidence against a database administrator; that is out of scope.
"""

import re
from typing import Optional

from pymongo.database import Database

from ..models.audit_event import AuditEvent


class AuditEventRepository:
    """Manages the ``audit_events`` collection. Insert-only by API surface."""

    COLLECTION = "audit_events"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]
        # Newest-first listing with the _id tiebreak, and one index per filter.
        self.collection.create_index([("timestamp", -1), ("_id", -1)])
        self.collection.create_index([("event", 1), ("timestamp", -1)])
        self.collection.create_index([("actor", 1), ("timestamp", -1)])
        self.collection.create_index([("target", 1), ("timestamp", -1)])

    def append(self, event: AuditEvent) -> None:
        """Insert one event."""
        self.collection.insert_one(event.to_dict())

    def search(
        self,
        *,
        limit: int,
        event_prefix: Optional[str] = None,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
        before_ts: Optional[str] = None,
        before_id: Optional[str] = None,
    ) -> list[AuditEvent]:
        """Newest first, at most ``limit``. ``event_prefix`` matches the start
        of the event name; ``actor`` and ``target`` match exactly;
        ``from_ts`` is inclusive and ``to_ts`` exclusive (canonical timestamp
        strings). Page older with the ``(before_ts, before_id)`` cursor of a
        prior page's last event."""
        clauses: list[dict] = []
        if event_prefix:
            clauses.append({"event": {"$regex": "^" + re.escape(event_prefix)}})
        if actor is not None:
            clauses.append({"actor": actor})
        if target is not None:
            clauses.append({"target": target})
        if from_ts is not None:
            clauses.append({"timestamp": {"$gte": from_ts}})
        if to_ts is not None:
            clauses.append({"timestamp": {"$lt": to_ts}})
        if before_ts is not None and before_id is not None:
            clauses.append({"$or": [
                {"timestamp": {"$lt": before_ts}},
                {"timestamp": before_ts, "_id": {"$lt": before_id}},
            ]})
        cur = (
            self.collection.find({"$and": clauses} if clauses else {})
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(max(1, limit))
        )
        return [AuditEvent.from_dict(doc) for doc in cur]
