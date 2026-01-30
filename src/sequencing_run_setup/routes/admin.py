"""Admin settings routes."""

from fasthtml.common import *
from starlette.responses import Response

from ..components.layout import AppShell
from ..components.admin import (
    AuthenticationPage,
    InstrumentConfigForm,
    InstrumentsPage,
    LDAPConfigForm,
    LDAPTestResult,
    ProfileSyncPage,
    ProfileSyncResult,
    SampleApiConfigForm,
    SampleApiPage,
)
from ..models.auth_config import AuthConfig, AuthMethod, LDAPConfig
from ..models.instrument_config import InstrumentConfig
from ..models.sample_api_config import SampleApiConfig
from ..models.user import UserRole
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
):
    """Register admin settings routes."""

    def require_admin(req):
        """Check if user is admin, return error response if not."""
        user = req.scope.get("auth")
        if not user or user.role != UserRole.ADMIN:
            return Response("Admin access required", status_code=403)
        return None

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
        instrument_config = get_instrument_config_repo().get()

        return AppShell(
            user=user,
            active_route="/admin/instruments",
            content=InstrumentsPage(instrument_config),
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
        except Exception as e:
            return LDAPTestResult(False, f"Unexpected error: {e}")

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
        except Exception as e:
            return LDAPTestResult(False, f"Authentication failed: {e}")

    @app.post("/admin/settings/instruments")
    def update_instrument_config(req, enabled_instruments: list[str] = None):
        """Update instrument visibility configuration."""
        error = require_admin(req)
        if error:
            return error

        if enabled_instruments is None:
            enabled_instruments = []

        from ..data.instruments import get_all_instruments

        all_instruments = get_all_instruments()
        config = InstrumentConfig()
        for inst in all_instruments:
            config.set_instrument_enabled(inst["name"], inst["name"] in enabled_instruments)

        get_instrument_config_repo().save(config)

        return InstrumentConfigForm(config, message="Instrument visibility settings saved")

    # Profile Sync Routes (only if repos are provided)
    if get_profile_sync_config_repo is not None:

        @app.get("/admin/profiles")
        def admin_profiles(req):
            """Profile sync configuration and status page."""
            error = require_admin(req)
            if error:
                return error

            user = req.scope.get("auth")
            config = get_profile_sync_config_repo().get()
            app_profiles = get_app_profile_repo().list_all() if get_app_profile_repo else []
            test_profiles = get_test_profile_repo().list_all() if get_test_profile_repo else []

            return AppShell(
                user=user,
                active_route="/admin/profiles",
                content=ProfileSyncPage(config, app_profiles, test_profiles),
                title="Profile Sync",
            )

        @app.post("/admin/profiles/config")
        def update_profile_sync_config(
            req,
            github_repo_url: str = "",
            github_branch: str = "main",
            test_profiles_path: str = "test_profiles/",
            application_profiles_path: str = "application_profiles/",
            sync_enabled: str = "",
            sync_interval_minutes: int = 60,
        ):
            """Update profile sync configuration."""
            error = require_admin(req)
            if error:
                return error

            config_repo = get_profile_sync_config_repo()
            config = config_repo.get()

            config.github_repo_url = github_repo_url
            config.github_branch = github_branch
            config.test_profiles_path = test_profiles_path
            config.application_profiles_path = application_profiles_path
            config.sync_enabled = sync_enabled == "on"
            config.sync_interval_minutes = sync_interval_minutes

            config_repo.save(config)

            app_profiles = get_app_profile_repo().list_all() if get_app_profile_repo else []
            test_profiles = get_test_profile_repo().list_all() if get_test_profile_repo else []

            return ProfileSyncPage(config, app_profiles, test_profiles, message="Configuration saved")

        @app.post("/admin/profiles/sync")
        def trigger_manual_sync(req):
            """Trigger manual profile sync."""
            error = require_admin(req)
            if error:
                return error

            if get_github_sync_service is None:
                return ProfileSyncPage(
                    get_profile_sync_config_repo().get(),
                    [],
                    [],
                    message="Sync service not available",
                )

            sync_service = get_github_sync_service()
            success, message, count = sync_service.sync()

            # Reload config and profiles to show updated data
            config = get_profile_sync_config_repo().get()
            app_profiles = get_app_profile_repo().list_all() if get_app_profile_repo else []
            test_profiles = get_test_profile_repo().list_all() if get_test_profile_repo else []

            return ProfileSyncPage(config, app_profiles, test_profiles, message=message)

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
                title="Sample API",
            )

        @app.post("/admin/settings/sample-api")
        def update_sample_api_config(
            req,
            base_url: str = "",
            api_key: str = "",
            enabled: str = "",
        ):
            """Update sample API configuration."""
            error = require_admin(req)
            if error:
                return error

            config_repo = get_sample_api_config_repo()
            existing_config = config_repo.get()

            config = SampleApiConfig(
                base_url=base_url,
                api_key=api_key if api_key else existing_config.api_key,
                enabled=enabled == "on",
            )
            config_repo.save(config)

            return SampleApiConfigForm(config, message="Sample API configuration saved")
