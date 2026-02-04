"""Application context for dependency injection."""

from dataclasses import dataclass
from typing import Optional

from .repositories import IndexKitRepository, RunRepository, TestRepository
from .repositories.application_profile_repo import ApplicationProfileRepository
from .repositories.auth_config_repo import AuthConfigRepository
from .repositories.instrument_config_repo import InstrumentConfigRepository
from .repositories.sample_api_config_repo import SampleApiConfigRepository
from .repositories.test_profile_repo import TestProfileRepository


@dataclass
class AppContext:
    """
    Central context object holding all application repositories.

    This replaces passing individual repository getters to route modules,
    providing a cleaner API and making dependencies explicit.

    Usage:
        ctx = AppContext(
            run_repo=get_run_repo(),
            index_kit_repo=get_index_kit_repo(),
            ...
        )
        # In routes:
        run = ctx.run_repo.get(run_id)
    """

    # Core repositories (always required)
    run_repo: RunRepository
    index_kit_repo: IndexKitRepository
    test_repo: TestRepository

    # Optional repositories (may be None if feature not configured)
    test_profile_repo: Optional[TestProfileRepository] = None
    app_profile_repo: Optional[ApplicationProfileRepository] = None
    instrument_config_repo: Optional[InstrumentConfigRepository] = None
    auth_config_repo: Optional[AuthConfigRepository] = None
    sample_api_config_repo: Optional[SampleApiConfigRepository] = None

    @property
    def instrument_config(self):
        """Get the current instrument configuration, or None if not configured."""
        if self.instrument_config_repo is None:
            return None
        return self.instrument_config_repo.get()

    @property
    def auth_config(self):
        """Get the current auth configuration, or None if not configured."""
        if self.auth_config_repo is None:
            return None
        return self.auth_config_repo.get()

    @property
    def sample_api_config(self):
        """Get the current sample API configuration, or None if not configured."""
        if self.sample_api_config_repo is None:
            return None
        return self.sample_api_config_repo.get()
