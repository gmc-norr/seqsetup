"""Repository for profile sync configuration."""

from ..models.profile_sync_config import ProfileSyncConfig
from .base import SingletonConfigRepository
from ..utils.clock import utcnow


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
