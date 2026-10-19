"""Background scheduler for periodic profile synchronization."""

import logging
import threading
import time

from .audit_log import audit, audit_text, redact_url
from ..input_rules.problems import AUDIT_BUDGET, bounded_report
from .github_sync import STAYS_PAUSED, GitHubSyncService
from ..repositories.profile_sync_config_repo import ProfileSyncConfigRepository
from ..utils.clock import utcnow


logger = logging.getLogger(__name__)

# Not every minute: GitHub limits unauthenticated API calls.
_RETRY_WHILE_PAUSED_SECONDS = 5 * 60


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
        # Capture the configured repo URL for the audit trail so a post-hoc
        # reader knows which reference-data source was applied. The interactive
        # /admin/config-sync trigger already audits via the route; the cron
        # path was unaudited prior to this — clinical reference data is being
        # replaced by a non-interactive job and that has to leave a record.
        audit(
            "config_sync.scheduled.started",
            actor="scheduler",
            target=redact_url(config.github_repo_url),
        )
        result = self.sync_service.sync()
        success, message, count = result
        # The message and problems, cut to fit an audit row: details over
        # 64 KiB would be dropped whole.
        report = bounded_report(message, getattr(result, "problems", []), AUDIT_BUDGET, clean=audit_text)

        if success:
            logger.info(f"Scheduled sync completed: {message}")
            audit(
                "config_sync.scheduled.completed",
                actor="scheduler",
                target=redact_url(config.github_repo_url),
                outcome="success",
                items=count,
                **report,
            )
        else:
            logger.error(f"Scheduled sync failed: {message}")
            audit(
                "config_sync.scheduled.completed",
                actor="scheduler",
                target=redact_url(config.github_repo_url),
                outcome="failure",
                **report,
            )

    def _should_sync(self, config) -> bool:
        """Check if enough time has passed since last sync."""
        if config.last_sync_at is None:
            return True

        elapsed = utcnow() - config.last_sync_at
        interval_seconds = config.sync_interval_minutes * 60
        # While a sync that stopped part-way keeps Mark Ready paused, try
        # again after a few minutes, not the whole interval (review P2-3,
        # 2026-10-14). Not when the last sync finished and still could not
        # lift it: another would not either (second review P3-2).
        if (self.config_repo.writing_since() is not None
                and STAYS_PAUSED not in (config.last_sync_message or "")):
            interval_seconds = min(interval_seconds, _RETRY_WHILE_PAUSED_SECONDS)

        return elapsed.total_seconds() >= interval_seconds

    @property
    def is_running(self) -> bool:
        """Check if the scheduler is running."""
        return self._running
