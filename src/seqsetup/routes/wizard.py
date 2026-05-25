"""Wizard routes for creating new runs and adding samples.

Migrated to Starlette ``Route(...)`` registration. FT components are
wrapped via ``ft_page_response`` to keep the shared app shell.
"""

from fasthtml.common import Div, H2, H3, P
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..components.wizard import (
    WizardStep1,
)
from ..context import AppContext
from ..templating import ft_page_response, ft_to_html, render as render_jinja, templates


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
            if existing else [s.id for s in run.samples]
        )
        existing_ids_param = ",".join(existing_sample_ids) if existing_sample_ids else ""

        from ..components.wizard.sample_table import SamplePasteFormatHelp, FetchFromApiSection
        paste_format_help_html = ft_to_html(SamplePasteFormatHelp())
        fetch_from_api_html = (
            ft_to_html(FetchFromApiSection(run.id, target="#add-samples-result",
                                           context="add_step1", existing_ids=existing_ids_param))
            if _sample_api_enabled() else ""
        )

        steps_for_progress = [
            {"number": "1", "label": "Add Samples",
             "href": f"/runs/{run.id}/samples/add/step/1", "is_active": True, "is_completed": False},
            {"number": "2", "label": "Assign Indexes",
             "href": f"/runs/{run.id}/samples/add/step/2", "is_active": False, "is_completed": False},
        ]
        return render_jinja(request, "wizard/add_samples_step1.html", {
            "run": run,
            "existing_ids_param": existing_ids_param,
            "paste_format_help_html": paste_format_help_html,
            "fetch_from_api_html": fetch_from_api_html,
            "steps": steps_for_progress,
        })

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
        existing_ids_param = ",".join(existing_sample_ids)
        existing_ids_set = set(existing_sample_ids)
        new_samples = [s for s in run.samples if s.id not in existing_ids_set]
        samples_without_indexes = [s for s in new_samples if not s.has_index]
        all_have_indexes = len(samples_without_indexes) == 0

        index_kits = ctx.index_kit_repo.list_all()
        default_kit = index_kits[0] if index_kits else None

        from ..components.wizard.index_panel import IndexKitDropdown, IndexKitPanel
        from ..components.wizard.sample_table import NewSamplesTableWizard
        from fasthtml.common import P

        index_kit_dropdown_html = ft_to_html(
            IndexKitDropdown(index_kits, default_kit.name if default_kit else None)
        )
        index_kit_panel_html = ft_to_html(
            IndexKitPanel(default_kit)
            if default_kit
            else P("No index kits available.", cls="no-kits-message")
        )
        new_samples_table_html = ft_to_html(
            NewSamplesTableWizard(run, new_samples, index_kits,
                                  context="add_step2", existing_ids=existing_ids_param)
        ) if new_samples else ""

        steps_for_progress = [
            {"number": "1", "label": "Add Samples",
             "href": f"/runs/{run.id}/samples/add/step/1", "is_active": False, "is_completed": True},
            {"number": "2", "label": "Assign Indexes",
             "href": f"/runs/{run.id}/samples/add/step/2", "is_active": True, "is_completed": False},
        ]
        return render_jinja(request, "wizard/add_samples_step2.html", {
            "run": run,
            "existing_ids_param": existing_ids_param,
            "new_samples": new_samples,
            "all_have_indexes": all_have_indexes,
            "index_kit_dropdown_html": index_kit_dropdown_html,
            "index_kit_panel_html": index_kit_panel_html,
            "new_samples_table_html": new_samples_table_html,
            "steps": steps_for_progress,
        })

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
