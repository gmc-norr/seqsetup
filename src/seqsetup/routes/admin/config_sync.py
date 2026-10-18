"""Admin config-sync settings page.

GET  /admin/config-sync         — full page
POST /admin/config-sync/config  — save sync config; HTMX fragment swap
POST /admin/config-sync/sync    — trigger manual sync (state-transition
                                   action; kept as POST per REST: this
                                   is "do work", not "create resource")

Admin-only via router-level require_admin_dep.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from pydantic import BaseModel
from pydantic.functional_validators import BeforeValidator
from starlette.responses import HTMLResponse, Response

from ...context import AppContext
from ...input_rules.problems import AUDIT_BUDGET, bounded_report, path_text
from ...forms.validators import clamp, strip_and_truncate
from ...services.audit_log import audit
from ...services.github_sync import GitHubSyncError, GitHubSyncService, paused_page_message
from ...templating import render
from ..dependencies import get_ctx, require_admin_dep
from ..utils import get_username


router = APIRouter(
    tags=["admin-config-sync"],
    dependencies=[Depends(require_admin_dep)],
)


class ConfigSyncForm(BaseModel):
    """GitHub-sync configuration.

    All string fields CLAMP via strip_and_truncate.
    sync_interval_minutes CLAMP via clamp(1, 1440).
    Checkboxes default False; Pydantic lax coerces "on" -> True.
    """
    github_repo_url: Annotated[str, BeforeValidator(strip_and_truncate(1024))] = ""
    github_branch: Annotated[str, BeforeValidator(strip_and_truncate(128))] = "main"
    test_profiles_path: Annotated[str, BeforeValidator(strip_and_truncate(256))] = "test_profiles/"
    application_profiles_path: Annotated[str, BeforeValidator(strip_and_truncate(256))] = "application_profiles/"
    instruments_path: Annotated[str, BeforeValidator(strip_and_truncate(256))] = "instruments/"
    index_kits_path: Annotated[str, BeforeValidator(strip_and_truncate(256))] = "index_kits/"
    sync_enabled: bool = False
    sync_instruments_enabled: bool = False
    sync_index_kits_enabled: bool = False
    sync_interval_minutes: Annotated[int, BeforeValidator(clamp(1, 1440))] = 60


def _same_repo(saved: str, synced: str) -> bool:
    """True when the two URLs name one GitHub repository. The sync normalizes
    a trailing slash and a ``.git`` suffix away before fetching, so comparing
    the raw strings raised the alarm about a repository synced an hour ago
    (batch 4 review fix F). A URL neither parser can read falls back to the
    comparison as written."""
    if saved == synced:
        return True
    try:
        return (GitHubSyncService._parse_repo_url(saved)
                == GitHubSyncService._parse_repo_url(synced))
    except (GitHubSyncError, ValueError):
        return False


def _page_ctx(ctx: AppContext, message: str = "", message_ok: bool = True) -> dict:
    """Build the template context. Profiles are listed in the page
    sidebar; pre-resolve here so the template stays pure render.
    ``message_ok`` False shows the message as an error (spec 2026-10-07
    group A4, §1, decision 10)."""
    config = ctx.profile_sync_config_repo.get()
    app_profiles = ctx.app_profile_repo.list_all() if ctx.app_profile_repo else []
    test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
    # True only when the stored status is known to belong to another
    # repository or branch: a status stored before SeqSetup remembered which
    # one it read has no repo, and raises no alarm about one.
    last_sync_other_repo = bool(
        config.last_sync_repo_url
        and (not _same_repo(config.github_repo_url, config.last_sync_repo_url)
             or config.last_sync_branch != config.github_branch)
    )
    paused = ctx.profile_sync_config_repo.writing_note()
    return {
        "config": config,
        "app_profiles": app_profiles,
        "test_profiles": test_profiles,
        "last_sync_other_repo": last_sync_other_repo,
        # A sync that stopped part-way pauses Mark Ready (review P2-3).
        "paused_message": (paused_page_message(paused["since"], paused["collections"],
                                               config.sync_instruments_enabled)
                           if paused else ""),
        "message": message,
        "message_ok": message_ok,
        # The problems the input rules found in the last sync's files, each
        # with its file, line and place (docs/design/2026-10-18-input-rules-design.md).
        "sync_problems": [
            {**record, "where": path_text(tuple(record["path"]))}
            for record in config.last_sync_problems
        ],
        "sync_problems_left_out": config.last_sync_problems_left_out,
    }


@router.get("/admin/config-sync", response_class=HTMLResponse)
def admin_config_sync(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /admin/config-sync — full page (404 if sync repo not configured)."""
    if ctx.profile_sync_config_repo is None:
        return Response("Profile-sync config repo not configured", status_code=404)
    return render(request, "admin/config_sync.html", _page_ctx(ctx))


@router.post("/admin/config-sync/config", response_class=HTMLResponse)
def update_config_sync_config(
    request: Request,
    form: Annotated[ConfigSyncForm, Form()],
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/config-sync/config — save sync config; HTMX fragment swap."""
    if ctx.profile_sync_config_repo is None:
        return Response("Profile-sync config repo not configured", status_code=404)

    config = ctx.profile_sync_config_repo.get()
    config.github_repo_url = form.github_repo_url
    config.github_branch = form.github_branch
    config.test_profiles_path = form.test_profiles_path
    config.application_profiles_path = form.application_profiles_path
    config.instruments_path = form.instruments_path
    config.index_kits_path = form.index_kits_path
    config.sync_enabled = form.sync_enabled
    config.sync_instruments_enabled = form.sync_instruments_enabled
    config.sync_index_kits_enabled = form.sync_index_kits_enabled
    config.sync_interval_minutes = form.sync_interval_minutes

    ctx.profile_sync_config_repo.save(config)
    audit(
        "config_sync.updated",
        actor=get_username(request),
        target="profile_sync_config",
        repo_url=config.github_repo_url,
        branch=config.github_branch,
        sync_enabled=config.sync_enabled,
    )
    return render(
        request,
        "admin/config_sync.html",
        _page_ctx(ctx, message="Configuration saved"),
        block_name="config_sync_page",
    )


@router.post("/admin/config-sync/sync", response_class=HTMLResponse)
def trigger_manual_sync(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/config-sync/sync — trigger a manual GitHub sync.

    State-transition action ("do work"); kept as POST per REST.
    Returns the page fragment with the result message.
    """
    if ctx.profile_sync_config_repo is None:
        return Response("Profile-sync config repo not configured", status_code=404)
    if ctx.get_github_sync_service is None:
        return render(
            request,
            "admin/config_sync.html",
            _page_ctx(ctx, message="Sync service not available", message_ok=False),
            block_name="config_sync_page",
        )

    sync_service = ctx.get_github_sync_service()
    result = sync_service.sync()
    success, message, count = result
    # The row carries the sync's message and problems, cut to fit an audit
    # row: details over 64 KiB would be dropped whole.
    audit(
        "config_sync.triggered",
        actor=get_username(request),
        target="github_sync",
        outcome="success" if success else "failure",
        items_synced=count,
        **bounded_report(message, getattr(result, "problems", []), AUDIT_BUDGET),
    )
    # Bust the synced-instruments cache so the new sync is visible to the
    # instruments page immediately. The lazy import matches the existing
    # behaviour — keeps a startup-time circular import at bay.
    from ...data.instruments import clear_synced_instruments_cache
    clear_synced_instruments_cache()

    return render(
        request,
        "admin/config_sync.html",
        _page_ctx(ctx, message=message, message_ok=success),
        block_name="config_sync_page",
    )
