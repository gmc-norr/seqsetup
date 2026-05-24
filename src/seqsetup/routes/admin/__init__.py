"""Admin settings routes.

Migrated to Starlette ``Route(...)`` registration. Admin FT components
(ConfigSyncPage) are still rendered via the transitional
``ft_response`` / ``ft_page_response`` helpers — a later cleanup
converts them to Jinja2.

The authentication page has been migrated to APIRouter + Jinja2 in
``routes/admin/authentication.py``. The instruments page has been
migrated to ``routes/admin/instruments.py``. The sample-API page has
been migrated to ``routes/admin/sample_api.py``. The logs page has been
migrated to ``routes/admin/logs.py``.
"""

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ...components.admin import (
    ConfigSyncPage,
)
from ...context import AppContext
from ...services.audit_log import audit
from ...templating import ft_page_response, ft_response
from ..utils import get_username, require_admin, sanitize_string


def register(app, ctx: AppContext) -> None:
    """Register admin settings routes."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"admin.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

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

