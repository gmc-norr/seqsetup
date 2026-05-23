"""Edit run page route.

Migrated to Starlette ``Route(...)`` registration. The composed
``edit-run`` page is still rendered from FT components via
``ft_page_response``. Must be registered LAST among ``/runs/...`` routes
because ``{run_id}`` is a path catch-all.
"""

from fasthtml.common import Div, Fieldset, Legend
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..components.edit_run import (
    RunConfigPanelHorizontal,
    RunStatusBar,
    SampleTableSectionForRun,
    TopBarForRun,
)
from ..context import AppContext
from ..templating import ft_page_response


def register(app, ctx: AppContext) -> None:
    """Register the edit-run route on the parent Starlette app."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"main.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def edit_run(request: Request) -> Response:
        """GET /runs/{run_id} — full edit-run page."""
        run_id = request.path_params["run_id"]

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []

        # Stacked layout: status bar → top bar (validate + export) →
        # config (with metadata) → samples.
        content = Div(
            RunStatusBar(run),
            TopBarForRun(run),
            RunConfigPanelHorizontal(run),
            Fieldset(
                Legend("Samples"),
                SampleTableSectionForRun(run, ctx.index_kit_repo.list_all(), test_profiles),
                cls="config-panel samples-display",
            ),
            cls="edit-run-layout",
        )

        return ft_page_response(
            request,
            content,
            page_title=run.run_name or "Edit Run",
        )

    app.routes.append(Route("/runs/{run_id}", edit_run, methods=["GET"]))
