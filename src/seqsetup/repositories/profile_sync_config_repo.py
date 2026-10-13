"""Repository for profile sync configuration."""

from datetime import datetime
from typing import Iterable, Optional

from ..models.profile_sync_config import ProfileSyncConfig
from .base import SingletonConfigRepository
from ..utils.clock import utcnow


class ProfileSyncConfigRepository(SingletonConfigRepository[ProfileSyncConfig]):
    """Repository for managing profile sync configuration in MongoDB.

    Uses singleton pattern - only one configuration document exists.
    """

    CONFIG_ID = "profile_sync_config"
    MODEL_CLASS = ProfileSyncConfig
    # Its own document, so a save of the settings record cannot drop it.
    WRITING_ID = "profile_sync_writing"
    INSTRUMENT_SETTINGS = "instrument settings"

    def mark_writing(self, since: datetime, collection: str,
                     disabled_instruments: Iterable[str] = ()) -> None:
        """Note that a sync is about to replace ``collection``; it stays on
        the note until ``written`` strikes it off. ``since`` keeps the
        earliest start, and ``disabled_instruments`` adds to the names noted."""
        self.collection.update_one(
            {"_id": self.WRITING_ID},
            {"$min": {"since": since},
             "$addToSet": {"collections": collection,
                           "disabled_instruments": {"$each": sorted(disabled_instruments)}}},
            upsert=True,
        )

    def writing_note(self) -> Optional[dict]:
        """The note while it names a collection: ``since``, ``collections``
        and ``disabled_instruments``; else None."""
        doc = self.collection.find_one({"_id": self.WRITING_ID})
        if not doc or not doc.get("collections"):
            return None
        return {"since": doc["since"], "collections": list(doc["collections"]),
                "disabled_instruments": list(doc.get("disabled_instruments", []))}

    def writing_since(self) -> Optional[datetime]:
        note = self.writing_note()
        return note["since"] if note else None

    def written(self, collections: Iterable[str]) -> list[str]:
        """Strike ``collections`` off the note and return the ones still on
        it. The noted disabled instruments belong to the instrument settings
        and go with them; the note goes when it names nothing."""
        collections = list(collections)
        update: dict = {"$pull": {"collections": {"$in": collections}}}
        if self.INSTRUMENT_SETTINGS in collections:
            update["$set"] = {"disabled_instruments": []}
        self.collection.update_one({"_id": self.WRITING_ID}, update)
        self.collection.delete_one({"_id": self.WRITING_ID, "collections": {"$size": 0}})
        note = self.writing_note()
        return note["collections"] if note else []

    def update_sync_status(
        self,
        status: str,
        message: str,
        count: int,
        instruments_count: int = 0,
        index_kits_count: int = 0,
        repo_url: str = "",
        branch: str = "",
    ) -> None:
        """Update sync status after a sync operation.

        ``repo_url`` and ``branch`` are the ones the sync read, stored with
        the status so no page can show it under another repository.
        """
        config = self.get()
        config.last_sync_at = utcnow()
        config.last_sync_status = status
        config.last_sync_message = message
        config.last_sync_count = count
        config.last_instruments_sync_count = instruments_count
        config.last_index_kits_sync_count = index_kits_count
        config.last_sync_repo_url = repo_url
        config.last_sync_branch = branch
        self.save(config)
