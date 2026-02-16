"""Admin settings routes."""

import logging

from fasthtml.common import *
from starlette.responses import Response

logger = logging.getLogger("seqsetup")

from .utils import require_admin
from ..components.layout import AppShell
from ..components.admin import (
    AuthenticationPage,
    ConfigSyncPage,
    InstrumentsPage,
    LDAPConfigForm,
    LDAPTestResult,
    LogsPage,
    SampleApiConfigForm,
    SampleApiPage,
    SyncedInstrumentsSection,
)
from ..models.auth_config import AuthMethod, LDAPConfig
from ..models.sample_api_config import SampleApiConfig
from ..services.ldap import LDAPService, LDAPError


def register(
    app,
    rt,
    get_auth_config_repo,
    get_instrument_config_repo,
    get_profile_sync_config_repo=None,
    get_github_sync_service=None,
    get_app_profile_repo=None,
    get_test_profile_repo=None,
    get_sample_api_config_repo=None,
    get_instrument_definition_repo=None,
):
    """Register admin settings routes."""

    @app.get("/admin/authentication")
    def admin_authentication(req):
        """Authentication settings page."""
        error = require_admin(req)
        if error:
            return error

        user = req.scope.get("auth")
        auth_config = get_auth_config_repo().get()

        return AppShell(
            user=user,
            active_route="/admin/authentication",
            content=AuthenticationPage(auth_config),
            title="Authentication",
        )

    @app.get("/admin/instruments")
    def admin_instruments(req):
        """Instrument visibility settings page."""
        error = require_admin(req)
        if error:
            return error

        user = req.scope.get("auth")
        synced_instruments = []
        if get_instrument_definition_repo:
            synced_instruments = get_instrument_definition_repo().list_all()

        return AppShell(
            user=user,
            active_route="/admin/instruments",
            content=InstrumentsPage(synced_instruments),
            title="Instruments",
        )

    @app.post("/admin/settings/auth-method")
    def update_auth_method(req, auth_method: str, allow_local_fallback: str = ""):
        """Update authentication method."""
        error = require_admin(req)
        if error:
            return error

        auth_config_repo = get_auth_config_repo()
        config = auth_config_repo.get()

        try:
            config.auth_method = AuthMethod(auth_method)
        except ValueError:
            config.auth_method = AuthMethod.LOCAL

        config.allow_local_fallback = allow_local_fallback == "on"
        auth_config_repo.save(config)

        return LDAPConfigForm(config, message="Authentication method updated")

    @app.post("/admin/settings/ldap")
    def update_ldap_config(
        req,
        server_url: str = "",
        use_ssl: str = "",
        base_dn: str = "",
        bind_dn: str = "",
        bind_password: str = "",
        user_search_base: str = "",
        user_search_filter: str = "(sAMAccountName={username})",
        user_dn_pattern: str = "",
        username_attribute: str = "sAMAccountName",
        display_name_attribute: str = "displayName",
        email_attribute: str = "mail",
        admin_group_dn: str = "",
        user_group_dn: str = "",
        group_membership_attribute: str = "memberOf",
        connect_timeout: int = 10,
        receive_timeout: int = 10,
    ):
        """Update LDAP configuration."""
        error = require_admin(req)
        if error:
            return error

        auth_config_repo = get_auth_config_repo()
        config = auth_config_repo.get()

        config.ldap_config = LDAPConfig(
            server_url=server_url,
            use_ssl=use_ssl == "on",
            base_dn=base_dn,
            bind_dn=bind_dn,
            bind_password=bind_password if bind_password else config.ldap_config.bind_password,
            user_search_base=user_search_base,
            user_search_filter=user_search_filter,
            user_dn_pattern=user_dn_pattern,
            username_attribute=username_attribute,
            display_name_attribute=display_name_attribute,
            email_attribute=email_attribute,
            admin_group_dn=admin_group_dn,
            user_group_dn=user_group_dn,
            group_membership_attribute=group_membership_attribute,
            connect_timeout=connect_timeout,
            receive_timeout=receive_timeout,
        )
        config.ldap_configured = bool(server_url and base_dn)
        config.ldap_tested = False  # Reset tested flag when config changes
        auth_config_repo.save(config)

        return LDAPConfigForm(config, message="LDAP configuration saved")

    @app.post("/admin/settings/ldap/test")
    def test_ldap_connection(req):
        """Test LDAP connection with current settings."""
        error = require_admin(req)
        if error:
            return error

        auth_config_repo = get_auth_config_repo()
        config = auth_config_repo.get()

        if not config.ldap_config.server_url:
            return LDAPTestResult(False, "LDAP server URL is not configured")

        try:
            ldap_service = LDAPService(config.ldap_config)
            success, message = ldap_service.test_connection()

            if success:
                config.ldap_tested = True
                auth_config_repo.save(config)

            return LDAPTestResult(success, message)

        except LDAPError as e:
            return LDAPTestResult(False, str(e))
        except Exception:
            logger.exception("LDAP connection test failed unexpectedly")
            return LDAPTestResult(False, "Connection test failed unexpectedly")

    @app.post("/admin/settings/ldap/test-auth")
    def test_ldap_auth(req, test_username: str = "", test_password: str = ""):
        """Test LDAP authentication with a specific user."""
        error = require_admin(req)
        if error:
            return error

        if not test_username or not test_password:
            return LDAPTestResult(False, "Please provide both username and password")

        auth_config_repo = get_auth_config_repo()
        config = auth_config_repo.get()

        if not config.ldap_config.server_url:
            return LDAPTestResult(False, "LDAP server URL is not configured")

        try:
            ldap_service = LDAPService(config.ldap_config)
            user = ldap_service.authenticate(test_username, test_password)
            return LDAPTestResult(
                True,
                f"Authentication successful! User: {user.display_name}, Role: {user.role.value}",
            )
        except LDAPError as e:
            return LDAPTestResult(False, str(e))
        except Exception:
            logger.exception("LDAP authentication test failed")
            return LDAPTestResult(False, "Authentication test failed")

    # Config Sync Routes (only if repos are provided)
    if get_profile_sync_config_repo is not None:

        @app.get("/admin/config-sync")
        def admin_config_sync(req):
            """Config sync configuration and status page."""
            error = require_admin(req)
            if error:
                return error

            user = req.scope.get("auth")
            config = get_profile_sync_config_repo().get()
            app_profiles = get_app_profile_repo().list_all() if get_app_profile_repo else []
            test_profiles = get_test_profile_repo().list_all() if get_test_profile_repo else []

            return AppShell(
                user=user,
                active_route="/admin/config-sync",
                content=ConfigSyncPage(config, app_profiles, test_profiles),
                title="Config Sync",
            )

        @app.post("/admin/config-sync/config")
        def update_config_sync_config(
            req,
            github_repo_url: str = "",
            github_branch: str = "main",
            test_profiles_path: str = "test_profiles/",
            application_profiles_path: str = "application_profiles/",
            instruments_path: str = "instruments/",
            index_kits_path: str = "index_kits/",
            sync_enabled: str = "",
            sync_instruments_enabled: str = "",
            sync_index_kits_enabled: str = "",
            sync_interval_minutes: int = 60,
        ):
            """Update config sync configuration."""
            error = require_admin(req)
            if error:
                return error

            config_repo = get_profile_sync_config_repo()
            config = config_repo.get()

            config.github_repo_url = github_repo_url
            config.github_branch = github_branch
            config.test_profiles_path = test_profiles_path
            config.application_profiles_path = application_profiles_path
            config.instruments_path = instruments_path
            config.index_kits_path = index_kits_path
            config.sync_enabled = sync_enabled == "on"
            config.sync_instruments_enabled = sync_instruments_enabled == "on"
            config.sync_index_kits_enabled = sync_index_kits_enabled == "on"
            config.sync_interval_minutes = sync_interval_minutes

            config_repo.save(config)

            app_profiles = get_app_profile_repo().list_all() if get_app_profile_repo else []
            test_profiles = get_test_profile_repo().list_all() if get_test_profile_repo else []

            return ConfigSyncPage(config, app_profiles, test_profiles, message="Configuration saved")

        @app.post("/admin/config-sync/sync")
        def trigger_manual_sync(req):
            """Trigger manual config sync."""
            error = require_admin(req)
            if error:
                return error

            if get_github_sync_service is None:
                return ConfigSyncPage(
                    get_profile_sync_config_repo().get(),
                    [],
                    [],
                    message="Sync service not available",
                )

            sync_service = get_github_sync_service()
            success, message, count = sync_service.sync()

            # Clear synced instruments cache to pick up new definitions
            from ..data.instruments import clear_synced_instruments_cache
            clear_synced_instruments_cache()

            # Reload config and profiles to show updated data
            config = get_profile_sync_config_repo().get()
            app_profiles = get_app_profile_repo().list_all() if get_app_profile_repo else []
            test_profiles = get_test_profile_repo().list_all() if get_test_profile_repo else []

            return ConfigSyncPage(config, app_profiles, test_profiles, message=message)

    # Sample API Routes (only if repo is provided)
    if get_sample_api_config_repo is not None:

        @app.get("/admin/sample-api")
        def admin_sample_api(req):
            """Sample API configuration page."""
            error = require_admin(req)
            if error:
                return error

            user = req.scope.get("auth")
            config = get_sample_api_config_repo().get()

            return AppShell(
                user=user,
                active_route="/admin/sample-api",
                content=SampleApiPage(config),
                title="LIMS Integration",
            )

        @app.post("/admin/settings/sample-api")
        def update_sample_api_config(
            req,
            base_url: str = "",
            api_key: str = "",
            enabled: str = "",
            field_worksheet_id: str = "",
            field_investigator: str = "",
            field_updated_at: str = "",
            field_samples: str = "",
        ):
            """Update sample API configuration."""
            error = require_admin(req)
            if error:
                return error

            config_repo = get_sample_api_config_repo()
            existing_config = config_repo.get()

            # Build field mappings dict from form inputs
            field_mappings = {}
            if field_worksheet_id.strip():
                field_mappings["worksheet_id"] = field_worksheet_id.strip()
            if field_investigator.strip():
                field_mappings["investigator"] = field_investigator.strip()
            if field_updated_at.strip():
                field_mappings["updated_at"] = field_updated_at.strip()
            if field_samples.strip():
                field_mappings["samples"] = field_samples.strip()

            config = SampleApiConfig(
                base_url=base_url,
                api_key=api_key if api_key else existing_config.api_key,
                enabled=enabled == "on",
                field_mappings=field_mappings,
            )

            # Test connection before enabling
            if config.enabled and config.base_url:
                from ..services.sample_api import check_connection
                success, msg = check_connection(config)
                if not success:
                    config.enabled = False
                    config_repo.save(config)
                    return SampleApiConfigForm(
                        config, error=f"Connection failed: {msg}. Integration has been disabled."
                    )

            config_repo.save(config)

            return SampleApiConfigForm(config, message="LIMS integration configuration saved")

    # Log Viewer Routes (always available)
    @app.get("/admin/logs")
    def admin_logs(req, level: str = "", search: str = ""):
        """Application logs viewer page."""
        error = require_admin(req)
        if error:
            return error

        from ..services.log_capture import get_captured_logs, get_log_stats

        user = req.scope.get("auth")
        entries = get_captured_logs(
            level=level if level else None,
            search=search if search else None,
            limit=200,
        )
        stats = get_log_stats()

        # For HTMX requests (Refresh/Filter buttons), return just the LogsPage component
        if req.headers.get("HX-Request"):
            return LogsPage(entries, stats, level, search)

        return AppShell(
            user=user,
            active_route="/admin/logs",
            content=LogsPage(entries, stats, level, search),
            title="Logs",
        )

    @app.post("/admin/logs/clear")
    def clear_logs(req):
        """Clear all captured logs."""
        error = require_admin(req)
        if error:
            return error

        from ..services.log_capture import clear_captured_logs, get_log_stats

        clear_captured_logs()
        stats = get_log_stats()

        return LogsPage([], stats, message="Logs cleared")

    # Synced Instruments Routes (only if repo is provided)
    if get_instrument_definition_repo is not None:

        @app.post("/admin/instruments/synced/toggle")
        async def toggle_synced_instrument(req):
            """Toggle the enabled status of a synced instrument."""
            error = require_admin(req)
            if error:
                return error

            form_data = await req.form()
            instrument_id = form_data.get("instrument_id", "")
            enabled_str = form_data.get("enabled", "true")
            enabled = enabled_str.lower() == "true"

            if instrument_id:
                get_instrument_definition_repo().set_enabled(instrument_id, enabled)

            # Return updated section
            instruments = get_instrument_definition_repo().list_all()
            return SyncedInstrumentsSection(instruments)

        @app.post("/admin/instruments/synced/enable-all")
        def enable_all_synced_instruments(req):
            """Enable all synced instruments."""
            error = require_admin(req)
            if error:
                return error

            repo = get_instrument_definition_repo()
            for inst in repo.list_all():
                repo.set_enabled(inst.id, True)

            instruments = repo.list_all()
            return SyncedInstrumentsSection(instruments, message="All instruments enabled")

        @app.post("/admin/instruments/synced/disable-all")
        def disable_all_synced_instruments(req):
            """Disable all synced instruments."""
            error = require_admin(req)
            if error:
                return error

            repo = get_instrument_definition_repo()
            for inst in repo.list_all():
                repo.set_enabled(inst.id, False)

            instruments = repo.list_all()
            return SyncedInstrumentsSection(instruments, message="All instruments disabled")
