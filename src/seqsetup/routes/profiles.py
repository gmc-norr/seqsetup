"""Profiles settings routes.

Migrated to Starlette ``Route(...)`` registration. The ProfilesPage FT
component is still rendered via the transitional ``ft_page_response``
helper; conversion to a Jinja2 template happens in a later cleanup PR.
"""

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..components.profiles import ProfilesPage
from ..context import AppContext
from ..services.version_resolver import resolve_application_profiles
from ..templating import ft_page_response


def register(app, ctx: AppContext) -> None:
    """Register profiles routes."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"profiles.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def profiles_page(request: Request) -> Response:
        """GET /profiles — overview page."""
        test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
        app_profiles = ctx.app_profile_repo.list_all() if ctx.app_profile_repo else []

        # Compute resolved application profiles in the route — the page
        # template stays purely a renderer.
        all_refs = []
        for tp in test_profiles:
            all_refs.extend(tp.application_profiles)
        resolved_map = resolve_application_profiles(all_refs, app_profiles)

        return ft_page_response(
            request,
            ProfilesPage(test_profiles, app_profiles, resolved_map=resolved_map),
            page_title="Profiles",
            active_route="/profiles",
        )

    app.routes.append(Route("/profiles", profiles_page, methods=["GET"]))
