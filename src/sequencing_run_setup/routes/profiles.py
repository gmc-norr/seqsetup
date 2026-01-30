"""Profiles settings routes."""

from fasthtml.common import *

from ..components.layout import AppShell
from ..components.profiles import ProfilesPage


def register(app, rt, get_test_profile_repo, get_app_profile_repo):
    """Register profiles routes."""

    @app.get("/profiles")
    def profiles_page(req):
        """Profiles overview page."""
        user = req.scope.get("auth")
        test_profiles = get_test_profile_repo().list_all()
        app_profiles = get_app_profile_repo().list_all()

        return AppShell(
            user=user,
            active_route="/profiles",
            content=ProfilesPage(test_profiles, app_profiles),
            title="Profiles",
        )
