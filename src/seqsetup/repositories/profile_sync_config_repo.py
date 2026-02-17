"""Repository for profile sync configuration."""

from datetime import datetime

from ..models.profile_sync_config import ProfileSyncConfig
from .base import SingletonConfigRepository


class ProfileSyncConfigRepository(SingletonConfigRepository[ProfileSyncConfig]):
    """Repository for managing profile sync configuration in MongoDB.

    Uses singleton pattern - only one configuration document exists.
    """

    CONFIG_ID = "profile_sync_config"
    MODEL_CLASS = ProfileSyncConfig

    def update_sync_status(
        self,
        status: str,
        message: str,
        count: int,
        instruments_count: int = 0,
        index_kits_count: int = 0,
    ) -> None:
        """Update sync status after a sync operation."""
        config = self.get()
        config.last_sync_at = datetime.now()
        config.last_sync_status = status
        config.last_sync_message = message
        config.last_sync_count = count
        config.last_instruments_sync_count = instruments_count
        config.last_index_kits_sync_count = index_kits_count
        self.save(config)
