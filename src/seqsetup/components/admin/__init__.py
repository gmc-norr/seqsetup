"""Admin settings page components.

This package splits the admin UI into focused submodules:
- authentication: Auth method selection, LDAP/AD configuration
- instruments: Instrument visibility settings
- config_sync: GitHub config sync configuration and status
- sample_api: LIMS/Sample API configuration
- logs: Application log viewer
"""

from .authentication import (
    AuthenticationPage,
    LDAPConfigForm,
    LDAPSettingsForm,
    LDAPTestResult,
)
from .instruments import (
    InstrumentsPage,
    SyncedInstrumentsSection,
)
from .config_sync import (
    ConfigSyncPage,
    ConfigSyncStatus,
    ConfigSyncConfigForm,
    ProfileSyncResult,
    ProfileListSection,
)
from .sample_api import (
    SampleApiPage,
    SampleApiConfigForm,
)
from .logs import (
    LogsPage,
    LogStats,
    LogFilters,
    LogEntriesTable,
)

__all__ = [
    # authentication
    "AuthenticationPage",
    "LDAPConfigForm",
    "LDAPSettingsForm",
    "LDAPTestResult",
    # instruments
    "InstrumentsPage",
    "SyncedInstrumentsSection",
    # config_sync
    "ConfigSyncPage",
    "ConfigSyncStatus",
    "ConfigSyncConfigForm",
    "ProfileSyncResult",
    "ProfileListSection",
    # sample_api
    "SampleApiPage",
    "SampleApiConfigForm",
    # logs
    "LogsPage",
    "LogStats",
    "LogFilters",
    "LogEntriesTable",
]
