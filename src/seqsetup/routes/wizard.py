"""Wizard routes for creating new runs and adding samples.

Migrated to Starlette ``Route(...)`` registration. FT components are
wrapped via ``ft_page_response`` to keep the shared app shell.
"""

from fasthtml.common import Div, H2, H3, P
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..components.wizard import (
    AddSamplesStep1,
    AddSamplesStep2,
    WizardStep1,
)
from ..context import AppContext
from ..templating import ft_page_response


def register(app, ctx: AppContext) -> None:
    """Register wizard routes on the parent Starlette app."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"wizard.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def _sample_api_enabled() -> bool:
        config = ctx.sample_api_config
        if config is None:
            return False
        return config.enabled and bool(config.base_url)

    # =========================================================================
    # New Run Wizard (single step - configuration only)
    # =========================================================================

    def wizard_new(request: Request) -> Response:
        """GET /runs/new — create the run row and redirect to step 1."""
        user = request.scope.get("auth")
        run = ctx.run_repo.create_run(user.username if user else "")
        return RedirectResponse(f"/runs/new/step/1?run_id={run.id}", status_code=303)

    def wizard_step1(request: Request) -> Response:
        """GET /runs/new/step/1 — wizard step 1: run configuration."""
        run_id = request.query_params.get("run_id", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        return ft_page_response(
            request,
            WizardStep1(run),
            page_title="New Run - Configuration",
        )

    # =========================================================================
    # Add Samples Wizard (2 steps - add samples, then assign indexes)
    # =========================================================================

    def add_samples_step1(request: Request) -> Response:
        """GET /runs/{run_id}/samples/add/step/1 — enter sample/test info."""
        run_id = request.path_params["run_id"]
        existing = request.query_params.get("existing", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        existing_sample_ids = (
            [sid.strip() for sid in existing.split(",") if sid.strip()]
            if existing else None
        )

        return ft_page_response(
            request,
            AddSamplesStep1(run, existing_sample_ids, sample_api_enabled=_sample_api_enabled()),
            page_title="Add Samples - Enter Sample Info",
        )

    def add_samples_step2(request: Request) -> Response:
        """GET /runs/{run_id}/samples/add/step/2 — assign indexes to samples."""
        run_id = request.path_params["run_id"]
        existing = request.query_params.get("existing", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        existing_sample_ids = (
            [sid.strip() for sid in existing.split(",") if sid.strip()]
            if existing else []
        )

        return ft_page_response(
            request,
            AddSamplesStep2(run, ctx.index_kit_repo.list_all(), existing_sample_ids),
            page_title="Add Samples - Assign Indexes",
        )

    def tests_page(request: Request) -> Response:
        """GET /tests — tests management page."""
        tests = ctx.test_repo.list_all()
        body = Div(
            H2("Tests Management"),
            P("Manage sequencing tests and assays.", cls="page-description"),
            Div(
                *[_TestCard(t) for t in tests] if tests else [
                    P("No tests configured yet.", cls="empty-message")
                ],
                cls="tests-list",
            ),
            cls="tests-page",
        )
        return ft_page_response(
            request,
            body,
            page_title="Tests",
            active_route="/tests",
        )

    app.routes.append(Route("/runs/new", wizard_new, methods=["GET"]))
    app.routes.append(Route("/runs/new/step/1", wizard_step1, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/samples/add/step/1", add_samples_step1, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/samples/add/step/2", add_samples_step2, methods=["GET"]))
    app.routes.append(Route("/tests", tests_page, methods=["GET"]))


def _TestCard(test):
    """Render a test card."""
    return Div(
        H3(test.name),
        P(test.description) if test.description else None,
        cls="test-card",
    )
