"""Validation context classes for explicit dependency management.

These context classes make ValidationService dependencies explicit,
replacing optional parameters with structured context objects.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..context import AppContext
    from ..models.instrument_config import InstrumentConfig
    from ..repositories.application_profile_repo import ApplicationProfileRepository
    from ..repositories.test_profile_repo import TestProfileRepository


@dataclass
class FullValidationContext:
    """
    Context for full validation including application profile checks.

    Use this context when you need complete validation with profile
    compatibility checks. Requires both test_profile_repo and app_profile_repo.
    """

    test_profile_repo: "TestProfileRepository"
    app_profile_repo: "ApplicationProfileRepository"
    instrument_config: Optional["InstrumentConfig"] = None

    @classmethod
    def from_app_context(cls, ctx: "AppContext") -> "FullValidationContext":
        """
        Create FullValidationContext from AppContext.

        Raises:
            ValueError: If required repositories are not available in AppContext
        """
        if ctx.test_profile_repo is None:
            raise ValueError(
                "FullValidationContext requires test_profile_repo, but AppContext has None"
            )
        if ctx.app_profile_repo is None:
            raise ValueError(
                "FullValidationContext requires app_profile_repo, but AppContext has None"
            )
        return cls(
            test_profile_repo=ctx.test_profile_repo,
            app_profile_repo=ctx.app_profile_repo,
            instrument_config=ctx.instrument_config,
        )

    @classmethod
    def from_app_context_optional(
        cls, ctx: "AppContext"
    ) -> Optional["FullValidationContext"]:
        """
        Create FullValidationContext from AppContext if repos are available.

        Returns None if either required repository is missing, instead of raising.
        """
        if ctx.test_profile_repo is None or ctx.app_profile_repo is None:
            return None
        return cls(
            test_profile_repo=ctx.test_profile_repo,
            app_profile_repo=ctx.app_profile_repo,
            instrument_config=ctx.instrument_config,
        )


@dataclass
class BasicValidationContext:
    """
    Context for basic validation without application profile checks.

    Use this context when you only need core validation (duplicates, collisions,
    color balance) without checking application profile compatibility.
    """

    instrument_config: Optional["InstrumentConfig"] = None

    @classmethod
    def from_app_context(cls, ctx: "AppContext") -> "BasicValidationContext":
        """Create BasicValidationContext from AppContext."""
        return cls(instrument_config=ctx.instrument_config)
