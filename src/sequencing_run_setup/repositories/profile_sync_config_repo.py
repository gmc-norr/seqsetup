"""Repository for profile sync configuration."""

from datetime import datetime

from pymongo.database import Database

from ..models.profile_sync_config import ProfileSyncConfig


class ProfileSyncConfigRepository:
    """Repository for managing profile sync configuration in MongoDB.

    Uses singleton pattern - only one configuration document exists.
    """

    CONFIG_ID = "profile_sync_config"

    def __init__(self, db: Database):
        self.collection = db["settings"]

    def get(self) -> ProfileSyncConfig:
        """Get the profile sync configuration, creating default if not exists."""
        doc = self.collection.find_one({"_id": self.CONFIG_ID})
        if doc:
            return ProfileSyncConfig.from_dict(doc.get("config", {}))
        return ProfileSyncConfig()

    def save(self, config: ProfileSyncConfig) -> None:
        """Save profile sync configuration."""
        self.collection.replace_one(
            {"_id": self.CONFIG_ID},
            {"_id": self.CONFIG_ID, "config": config.to_dict()},
            upsert=True,
        )

    def update_sync_status(
        self,
        status: str,
        message: str,
        count: int,
    ) -> None:
        """Update sync status after a sync operation."""
        config = self.get()
        config.last_sync_at = datetime.now()
        config.last_sync_status = status
        config.last_sync_message = message
        config.last_sync_count = count
        self.save(config)
