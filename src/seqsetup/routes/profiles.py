"""Profiles overview page — the canonical reference port for the HTMX
best-practices redesign.

Patterns demonstrated:
  - APIRouter with prefix + tags
  - get_ctx dependency (no closure-captured ctx)
  - response_class=HTMLResponse
  - render() with no block_name (full page)
  - Pre-computed template context (every value built in Python; template
    iterates only)

See ARCHITECTURE.md and the design spec at
docs/superpowers/specs/2026-05-24-htmx-best-practices-redesign-design.md
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse

from ..context import AppContext
from ..services.version_resolver import resolve_application_profiles
from ..templating import render
from .dependencies import get_ctx


router = APIRouter(prefix="", tags=["profiles"])


def _summarize_settings(settings: dict) -> str:
    """First three non-SoftwareVersion settings as ``"k: v, k: v, k: v, ..."``."""
    other = {k: v for k, v in settings.items() if k != "SoftwareVersion"}
    if not other:
        return ""
    summary = ", ".join(f"{k}: {v}" for k, v in list(other.items())[:3])
    if len(other) > 3:
        summary += ", ..."
    return summary


@router.get("/profiles", response_class=HTMLResponse)
def profiles_page(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
):
    test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
    app_profiles = ctx.app_profile_repo.list_all() if ctx.app_profile_repo else []

    all_refs = []
    for tp in test_profiles:
        all_refs.extend(tp.application_profiles)
    resolved_map = resolve_application_profiles(all_refs, app_profiles)

    app_profile_rows = [
        {
            "name": ap.name,
            "version": ap.version,
            "application_name": ap.application_name,
            "application_type": ap.application_type,
            "software_version": ap.settings.get("SoftwareVersion", "") if ap.settings else "",
            "settings_summary": _summarize_settings(ap.settings or {}),
        }
        for ap in sorted(app_profiles, key=lambda a: (a.application_name, a.name))
    ]

    return render(
        request,
        "profiles.html",
        {
            "test_profiles": test_profiles,
            "test_profiles_sorted": sorted(test_profiles, key=lambda t: t.test_type),
            "app_profiles": app_profiles,
            "app_profile_rows": app_profile_rows,
            "resolved_map": resolved_map,
        },
    )
