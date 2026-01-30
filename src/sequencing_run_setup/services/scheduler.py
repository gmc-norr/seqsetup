"""Background scheduler for periodic profile synchronization."""

import logging
import threading
import time
from datetime import datetime

from .github_sync import GitHubSyncService
from ..repositories.profile_sync_config_repo import ProfileSyncConfigRepository


logger = logging.getLogger(__name__)


class ProfileSyncScheduler:
    """Background scheduler for periodic profile sync.

    Runs in a daemon thread and checks every minute if a sync is due
    based on the configured interval.
    """

    def __init__(
        self,
        sync_service: GitHubSyncService,
        config_repo: ProfileSyncConfigRepository,
    ):
        self.sync_service = sync_service
        self.config_repo = config_repo
        self._running = False
        self._thread = None
        self._check_interval = 60  # Check every 60 seconds

    def start(self):
        """Start the background sync scheduler."""
        if self._running:
            logger.warning("Scheduler already running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Profile sync scheduler started")

    def stop(self):
        """Stop the scheduler."""
        if not self._running:
            return

        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Profile sync scheduler stopped")

    def _run_loop(self):
        """Main scheduler loop.

        Checks every minute if it's time to sync based on:
        - sync_enabled flag
        - github_repo_url is configured
        - sync_interval_minutes has elapsed since last sync
        """
        while self._running:
            try:
                self._check_and_sync()
            except Exception as e:
                logger.exception(f"Error in scheduler loop: {e}")

            # Sleep for check interval, but check _running periodically
            for _ in range(self._check_interval):
                if not self._running:
                    break
                time.sleep(1)

    def _check_and_sync(self):
        """Check if sync is due and perform it."""
        try:
            config = self.config_repo.get()
        except Exception as e:
            logger.error(f"Failed to get config: {e}")
            return

        # Check if sync is enabled and configured
        if not config.sync_enabled:
            return

        if not config.github_repo_url:
            return

        # Check if enough time has elapsed
        if not self._should_sync(config):
            return

        # Perform sync
        logger.info("Scheduled sync starting...")
        success, message, count = self.sync_service.sync()

        if success:
            logger.info(f"Scheduled sync completed: {message}")
        else:
            logger.error(f"Scheduled sync failed: {message}")

    def _should_sync(self, config) -> bool:
        """Check if enough time has passed since last sync."""
        if config.last_sync_at is None:
            return True

        elapsed = datetime.now() - config.last_sync_at
        interval_seconds = config.sync_interval_minutes * 60

        return elapsed.total_seconds() >= interval_seconds

    @property
    def is_running(self) -> bool:
        """Check if the scheduler is running."""
        return self._running
