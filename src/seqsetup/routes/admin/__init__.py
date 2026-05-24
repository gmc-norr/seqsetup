"""Admin settings routes.

Migrated to Starlette ``Route(...)`` registration. Admin FT components
(AuthenticationPage, LDAPConfigForm, ConfigSyncPage, LogsPage) are still
rendered via the transitional ``ft_response`` / ``ft_page_response``
helpers — a later cleanup converts them to Jinja2.

The instruments page has been migrated to APIRouter + Jinja2 in
``routes/admin/instruments.py``. The sample-API page has been migrated to
``routes/admin/sample_api.py``.
"""

import logging

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ...components.admin import (
    AuthenticationPage,
    ConfigSyncPage,
    LDAPConfigForm,
    LDAPTestResult,
    LogsPage,
)
from ...context import AppContext
from ...models.auth_config import AuthMethod, LDAPConfig, validate_user_dn_pattern
from ...rate_limit import client_identity, get_login_limiter
from ...services.audit_log import audit
from ...services.ldap import LDAPService, LDAPError
from ...templating import ft_page_response, ft_response
from ..utils import get_username, require_admin, sanitize_string


logger = logging.getLogger("seqsetup")


def register(app, ctx: AppContext) -> None:
    """Register admin settings routes."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"admin.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    # ---- Authentication settings ---------------------------------------

    def admin_authentication(request: Request) -> Response:
        if err := require_admin(request):
            return err
        return ft_page_response(
            request,
            AuthenticationPage(ctx.auth_config_repo.get()),
            page_title="Authentication",
            active_route="/admin/authentication",
        )

    async def update_auth_method(request: Request) -> Response:
        if err := require_admin(request):
            return err
        form = await request.form()
        auth_method = form.get("auth_method", "")
        allow_local_fallback = form.get("allow_local_fallback", "")

        config = ctx.auth_config_repo.get()
        try:
            config.auth_method = AuthMethod(auth_method)
        except ValueError:
            config.auth_method = AuthMethod.LOCAL
        config.allow_local_fallback = allow_local_fallback == "on"
        ctx.auth_config_repo.save(config)
        audit(
            "auth.method.changed",
            actor=get_username(request),
            target="auth_config",
            method=config.auth_method.value,
            allow_local_fallback=config.allow_local_fallback,
        )
        return ft_response(LDAPConfigForm(config, message="Authentication method updated"))

    async def update_ldap_config(request: Request) -> Response:
        if err := require_admin(request):
            return err
        form = await request.form()
        user_dn_pattern = form.get("user_dn_pattern", "")

        # Reject DN-template injection attempts before persisting.
        try:
            validate_user_dn_pattern(user_dn_pattern)
        except ValueError as e:
            return Response(str(e), status_code=400)

        config = ctx.auth_config_repo.get()
        bind_password = form.get("bind_password", "")
        config.ldap_config = LDAPConfig(
            server_url=form.get("server_url", ""),
            use_ssl=form.get("use_ssl", "") == "on",
            verify_ssl_cert=form.get("verify_ssl_cert", "on") == "on",
            base_dn=form.get("base_dn", ""),
            bind_dn=form.get("bind_dn", ""),
            bind_password=bind_password if bind_password else config.ldap_config.bind_password,
            user_search_base=form.get("user_search_base", ""),
            user_search_filter=form.get("user_search_filter", "(sAMAccountName={username})"),
            user_dn_pattern=user_dn_pattern,
            username_attribute=form.get("username_attribute", "sAMAccountName"),
            display_name_attribute=form.get("display_name_attribute", "displayName"),
            email_attribute=form.get("email_attribute", "mail"),
            admin_group_dn=form.get("admin_group_dn", ""),
            user_group_dn=form.get("user_group_dn", ""),
            group_membership_attribute=form.get("group_membership_attribute", "memberOf"),
            connect_timeout=int(form.get("connect_timeout", "10") or 10),
            receive_timeout=int(form.get("receive_timeout", "10") or 10),
        )
        config.ldap_configured = bool(config.ldap_config.server_url and config.ldap_config.base_dn)
        config.ldap_tested = False
        ctx.auth_config_repo.save(config)
        audit(
            "auth.ldap_config.updated",
            actor=get_username(request),
            target="ldap_config",
            server_url=config.ldap_config.server_url,
            base_dn=config.ldap_config.base_dn,
            bind_dn=config.ldap_config.bind_dn,
        )
        return ft_response(LDAPConfigForm(config, message="LDAP configuration saved"))

    def test_ldap_connection(request: Request) -> Response:
        if err := require_admin(request):
            return err
        config = ctx.auth_config_repo.get()
        if not config.ldap_config.server_url:
            return ft_response(LDAPTestResult(False, "LDAP server URL is not configured"))
        try:
            ldap_service = LDAPService(config.ldap_config)
            success, message = ldap_service.test_connection()
            if success:
                config.ldap_tested = True
                ctx.auth_config_repo.save(config)
            return ft_response(LDAPTestResult(success, message))
        except LDAPError as e:
            return ft_response(LDAPTestResult(False, str(e)))
        except Exception:
            logger.exception("LDAP connection test failed unexpectedly")
            return ft_response(LDAPTestResult(False, "Connection test failed unexpectedly"))

    async def test_ldap_auth(request: Request) -> Response:
        """Same rate-limiting policy as /login/submit — this endpoint
        triggers a real LDAP bind from admin-supplied credentials.
        """
        if err := require_admin(request):
            return err
        form = await request.form()
        test_username = form.get("test_username", "")
        test_password = form.get("test_password", "")

        if not test_username or not test_password:
            return ft_response(LDAPTestResult(False, "Please provide both username and password"))

        limiter = get_login_limiter()
        ip = client_identity(request)
        actor_user = (test_username or "")[:128].lower()
        ok_ip, retry_ip = limiter.allow(f"ldap-test-ip:{ip}")
        ok_user, retry_user = limiter.allow(f"ldap-test-user:{actor_user}")
        if not (ok_ip and ok_user):
            retry = max(retry_ip, retry_user)
            audit(
                "ldap.test_auth.rate_limited",
                actor=get_username(request),
                outcome="denied",
                ip=ip,
                target_user=actor_user,
                retry_after=retry,
            )
            return ft_response(LDAPTestResult(False, f"Too many test attempts. Retry after {retry}s."))

        config = ctx.auth_config_repo.get()
        if not config.ldap_config.server_url:
            return ft_response(LDAPTestResult(False, "LDAP server URL is not configured"))
        try:
            ldap_service = LDAPService(config.ldap_config)
            user = ldap_service.authenticate(test_username, test_password)
            return ft_response(LDAPTestResult(
                True,
                f"Authentication successful! User: {user.display_name}, Role: {user.role.value}",
            ))
        except LDAPError as e:
            return ft_response(LDAPTestResult(False, str(e)))
        except Exception:
            logger.exception("LDAP authentication test failed")
            return ft_response(LDAPTestResult(False, "Authentication test failed"))

    app.routes.append(Route("/admin/authentication", admin_authentication, methods=["GET"]))
    app.routes.append(Route("/admin/settings/auth-method", update_auth_method, methods=["POST"]))
    app.routes.append(Route("/admin/settings/ldap", update_ldap_config, methods=["POST"]))
    app.routes.append(Route("/admin/settings/ldap/test", test_ldap_connection, methods=["POST"]))
    app.routes.append(Route("/admin/settings/ldap/test-auth", test_ldap_auth, methods=["POST"]))

    # ---- Config Sync (only if repo is available) ----------------------

    if ctx.profile_sync_config_repo is not None:

        def admin_config_sync(request: Request) -> Response:
            if err := require_admin(request):
                return err
            config = ctx.profile_sync_config_repo.get()
            app_profiles = ctx.app_profile_repo.list_all() if ctx.app_profile_repo else []
            test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
            return ft_page_response(
                request,
                ConfigSyncPage(config, app_profiles, test_profiles),
                page_title="Config Sync",
                active_route="/admin/config-sync",
            )

        async def update_config_sync_config(request: Request) -> Response:
            if err := require_admin(request):
                return err
            form = await request.form()
            config = ctx.profile_sync_config_repo.get()
            config.github_repo_url = sanitize_string(form.get("github_repo_url", ""), 1024)
            config.github_branch = sanitize_string(form.get("github_branch", "main"), 128)
            config.test_profiles_path = sanitize_string(form.get("test_profiles_path", "test_profiles/"), 256)
            config.application_profiles_path = sanitize_string(form.get("application_profiles_path", "application_profiles/"), 256)
            config.instruments_path = sanitize_string(form.get("instruments_path", "instruments/"), 256)
            config.index_kits_path = sanitize_string(form.get("index_kits_path", "index_kits/"), 256)
            config.sync_enabled = form.get("sync_enabled", "") == "on"
            config.sync_instruments_enabled = form.get("sync_instruments_enabled", "") == "on"
            config.sync_index_kits_enabled = form.get("sync_index_kits_enabled", "") == "on"
            try:
                interval = int(form.get("sync_interval_minutes", "60") or 60)
            except ValueError:
                interval = 60
            config.sync_interval_minutes = max(1, min(1440, interval))

            ctx.profile_sync_config_repo.save(config)
            audit(
                "config_sync.updated",
                actor=get_username(request),
                target="profile_sync_config",
                repo_url=config.github_repo_url,
                branch=config.github_branch,
                sync_enabled=config.sync_enabled,
            )
            app_profiles = ctx.app_profile_repo.list_all() if ctx.app_profile_repo else []
            test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
            return ft_response(ConfigSyncPage(config, app_profiles, test_profiles, message="Configuration saved"))

        def trigger_manual_sync(request: Request) -> Response:
            if err := require_admin(request):
                return err
            if ctx.get_github_sync_service is None:
                return ft_response(
                    ConfigSyncPage(
                        ctx.profile_sync_config_repo.get(),
                        [], [],
                        message="Sync service not available",
                    )
                )
            sync_service = ctx.get_github_sync_service()
            success, message, count = sync_service.sync()
            audit(
                "config_sync.triggered",
                actor=get_username(request),
                target="github_sync",
                outcome="success" if success else "failure",
                items_synced=count,
            )
            from ...data.instruments import clear_synced_instruments_cache
            clear_synced_instruments_cache()

            config = ctx.profile_sync_config_repo.get()
            app_profiles = ctx.app_profile_repo.list_all() if ctx.app_profile_repo else []
            test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
            return ft_response(ConfigSyncPage(config, app_profiles, test_profiles, message=message))

        app.routes.append(Route("/admin/config-sync", admin_config_sync, methods=["GET"]))
        app.routes.append(Route("/admin/config-sync/config", update_config_sync_config, methods=["POST"]))
        app.routes.append(Route("/admin/config-sync/sync", trigger_manual_sync, methods=["POST"]))

    # ---- Logs ----------------------------------------------------------

    def admin_logs(request: Request) -> Response:
        if err := require_admin(request):
            return err
        from ...services.log_capture import get_captured_logs, get_log_stats

        level = request.query_params.get("level", "") or None
        search = request.query_params.get("search", "") or None
        entries = get_captured_logs(level=level, search=search, limit=200)
        stats = get_log_stats()

        # HTMX refresh: just the LogsPage fragment.
        if request.headers.get("HX-Request"):
            return ft_response(LogsPage(entries, stats, level or "", search or ""))
        return ft_page_response(
            request,
            LogsPage(entries, stats, level or "", search or ""),
            page_title="Logs",
            active_route="/admin/logs",
        )

    def clear_logs(request: Request) -> Response:
        if err := require_admin(request):
            return err
        from ...services.log_capture import clear_captured_logs, get_log_stats
        clear_captured_logs()
        audit("logs.cleared", actor=get_username(request), target="log_buffer")
        return ft_response(LogsPage([], get_log_stats(), message="Logs cleared"))

    app.routes.append(Route("/admin/logs", admin_logs, methods=["GET"]))
    app.routes.append(Route("/admin/logs/clear", clear_logs, methods=["POST"]))
