"""Profiles settings routes."""

from fasthtml.common import *

from ..components.layout import AppShell
from ..components.profiles import ProfilesPage
from ..context import AppContext
from ..services.version_resolver import resolve_application_profiles


def register(app, rt, ctx: AppContext):
    """Register profiles routes."""

    @app.get("/profiles")
    def profiles_page(req):
        """Profiles overview page."""
        user = req.scope.get("auth")
        test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
        app_profiles = ctx.app_profile_repo.list_all() if ctx.app_profile_repo else []

        # Compute resolved application profiles in route
        all_refs = []
        for tp in test_profiles:
            all_refs.extend(tp.application_profiles)
        resolved_map = resolve_application_profiles(all_refs, app_profiles)

        return AppShell(
            user=user,
            active_route="/profiles",
            content=ProfilesPage(test_profiles, app_profiles, resolved_map=resolved_map),
            title="Profiles",
        )
