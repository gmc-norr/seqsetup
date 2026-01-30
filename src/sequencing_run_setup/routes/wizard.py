"""Wizard routes for creating new runs and adding samples."""

from fasthtml.common import *
from starlette.responses import RedirectResponse

from ..components.layout import AppShell
from ..components.wizard import (
    WizardStep1,
    AddSamplesStep1,
    AddSamplesStep2,
)


def register(app, rt, get_run_repo, get_index_kit_repo, get_test_repo, get_sample_api_config_repo=None):
    """Register wizard routes."""

    def _sample_api_enabled():
        """Check if sample API is configured and enabled."""
        if get_sample_api_config_repo is None:
            return False
        config = get_sample_api_config_repo().get()
        return config.enabled and bool(config.api_url)

    # =========================================================================
    # New Run Wizard (single step - configuration only)
    # =========================================================================

    @app.get("/runs/new")
    def wizard_new(req):
        """Start a new run wizard - create run and redirect to step 1."""
        run_repo = get_run_repo()
        user = req.scope.get("auth")
        run = run_repo.create_run(user.username if user else "")
        return RedirectResponse(f"/runs/new/step/1?run_id={run.id}", status_code=303)

    @app.get("/runs/new/step/1")
    def wizard_step1(req, run_id: str):
        """Wizard Step 1: Run Configuration."""
        run_repo = get_run_repo()
        user = req.scope.get("auth")

        run = run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        return AppShell(
            user=user,
            active_route=None,
            content=WizardStep1(run),
            title="New Run - Configuration",
        )

    # =========================================================================
    # Add Samples Wizard (2 steps - add samples, then assign indexes)
    # =========================================================================

    @app.get("/runs/{run_id}/samples/add/step/1")
    def add_samples_step1(req, run_id: str, existing: str = ""):
        """Add Samples Wizard Step 1: Add samples with sample_id and test_id."""
        run_repo = get_run_repo()
        user = req.scope.get("auth")

        run = run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        # Parse existing sample IDs from query param (for Back navigation)
        existing_sample_ids = [id.strip() for id in existing.split(",") if id.strip()] if existing else None

        return AppShell(
            user=user,
            active_route=None,
            content=AddSamplesStep1(run, existing_sample_ids, sample_api_enabled=_sample_api_enabled()),
            title="Add Samples - Enter Sample Info",
        )

    @app.get("/runs/{run_id}/samples/add/step/2")
    def add_samples_step2(req, run_id: str, existing: str = ""):
        """Add Samples Wizard Step 2: Assign indexes to samples."""
        run_repo = get_run_repo()
        index_kit_repo = get_index_kit_repo()
        user = req.scope.get("auth")

        run = run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        # Parse existing sample IDs from query param
        existing_sample_ids = [id.strip() for id in existing.split(",") if id.strip()] if existing else []

        return AppShell(
            user=user,
            active_route=None,
            content=AddSamplesStep2(run, index_kit_repo.list_all(), existing_sample_ids),
            title="Add Samples - Assign Indexes",
        )

    @app.get("/tests")
    def tests_page(req):
        """Tests management page."""
        test_repo = get_test_repo()
        user = req.scope.get("auth")
        tests = test_repo.list_all()

        return AppShell(
            user=user,
            active_route="/tests",
            content=Div(
                H2("Tests Management"),
                P("Manage sequencing tests and assays.", cls="page-description"),
                Div(
                    *[TestCard(t) for t in tests] if tests else [
                        P("No tests configured yet.", cls="empty-message")
                    ],
                    cls="tests-list",
                ),
                cls="tests-page",
            ),
            title="Tests",
        )


def TestCard(test):
    """Render a test card."""
    return Div(
        H3(test.name),
        P(test.description) if test.description else None,
        cls="test-card",
    )
