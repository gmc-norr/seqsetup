"""Edit run page routes."""

from fasthtml.common import *
from starlette.responses import RedirectResponse

from ..components.edit_run import (
    ExportPanelForRun,
    RunConfigPanelHorizontal,
    RunStatusBar,
    SampleTableSectionForRun,
    TopBarForRun,
)
from ..components.layout import AppShell
from ..context import AppContext


def register(app, rt, ctx: AppContext):
    """Register main page routes."""

    @rt("/runs/{run_id}")
    def edit_run(req, run_id: str):
        """Render the edit run page with config above samples."""
        user = req.scope.get("auth")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        # Get test profiles for the dropdown
        test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []

        # Stacked layout: status bar, top bar (validate + export), config (with metadata), then samples
        content = Div(
            # Run status bar with transition buttons
            RunStatusBar(run),
            # Top bar with Validate and Export panels
            TopBarForRun(run),
            # Run configuration (includes metadata)
            RunConfigPanelHorizontal(run),
            # Samples table at the bottom
            Fieldset(
                Legend("Samples"),
                SampleTableSectionForRun(run, ctx.index_kit_repo.list_all(), test_profiles),
                cls="config-panel samples-display",
            ),
            cls="edit-run-layout",
        )

        return AppShell(
            user=user,
            active_route=None,  # Not a main nav item
            content=content,
            title=run.run_name or "Edit Run",
        )
