"""Validation routes for index collision checking."""

from fasthtml.common import *
from starlette.responses import Response

from ..components.validation_panel import (
    HeatmapsTabContent,
    IssuesTabContent,
    LaneHeatmapContent,
    ValidationApprovalBar,
    ValidationErrorList,
    ValidationPage,
    ValidationPanel,
    ValidationTabs,
)
from ..services.validation import ValidationService


def _get_username(req) -> str:
    """Extract username from request auth scope."""
    user = req.scope.get("auth")
    return user.username if user else ""


def register(
    app,
    rt,
    get_run_repo,
    get_test_profile_repo=None,
    get_app_profile_repo=None,
    get_instrument_config_repo=None,
):
    """Register validation routes."""

    def _validate_run(run):
        """Run validation with profile repos if available."""
        instrument_config = get_instrument_config_repo().get() if get_instrument_config_repo else None
        return ValidationService.validate_run(
            run,
            test_profile_repo=get_test_profile_repo() if get_test_profile_repo else None,
            app_profile_repo=get_app_profile_repo() if get_app_profile_repo else None,
            instrument_config=instrument_config,
        )

    @rt("/runs/{run_id}/validation")
    def validation_page(req, run_id: str):
        """Display the full validation page for a run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)

        if not run:
            return Response("Run not found", status_code=404)

        user = req.scope.get("auth")
        result = _validate_run(run)
        return ValidationPage(run, user, result=result)

    @rt("/runs/{run_id}/validation/tab/issues")
    def get_issues_tab(run_id: str):
        """Get the Issues tab content (returns full tabs for proper button state)."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)

        if not run:
            return Div(P("Run not found"), cls="error")

        result = _validate_run(run)
        return ValidationTabs(run_id, result, active_tab="issues")

    @rt("/runs/{run_id}/validation/tab/heatmaps")
    def get_heatmaps_tab(run_id: str, type: str = "i7"):
        """Get the Heatmaps tab content with specified index type (returns full tabs for proper button state)."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)

        if not run:
            return Div(P("Run not found"), cls="error")

        result = _validate_run(run)
        return ValidationTabs(run_id, result, active_tab="heatmaps", index_type=type)

    @rt("/runs/{run_id}/validation/tab/colorbalance")
    def get_colorbalance_tab(run_id: str):
        """Get the Color Balance tab content (returns full tabs for proper button state)."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)

        if not run:
            return Div(P("Run not found"), cls="error")

        result = _validate_run(run)
        return ValidationTabs(run_id, result, active_tab="colorbalance")

    @rt("/runs/{run_id}/validation/tab/darkcycles")
    def get_darkcycles_tab(run_id: str):
        """Get the Dark Cycles tab content (returns full tabs for proper button state)."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)

        if not run:
            return Div(P("Run not found"), cls="error")

        result = _validate_run(run)
        return ValidationTabs(run_id, result, active_tab="darkcycles")

    @rt("/runs/{run_id}/validation/errors")
    def get_validation_errors(run_id: str):
        """Get just the validation errors (for quick refresh)."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)

        if not run:
            return Div(P("Run not found"), cls="error")

        result = _validate_run(run)
        return ValidationErrorList(result)

    @rt("/runs/{run_id}/validation/heatmap")
    def get_heatmap(run_id: str, lane: int = 1, type: str = "i7"):
        """Get heatmap for specific lane and index type (legacy endpoint)."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)

        if not run:
            return Div(P("Run not found"), cls="error")

        result = _validate_run(run)
        matrix = result.distance_matrices.get(lane)
        if matrix and len(matrix.sample_names) >= 2:
            return LaneHeatmapContent(run_id, lane, matrix, index_type=type)
        return Div(P(f"No samples in lane {lane}"), cls="info")

    @app.post("/runs/{run_id}/validation/approve")
    def approve_validation(req, run_id: str):
        """Approve validation for a run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        result = _validate_run(run)

        # Only allow approval if there are no errors
        can_approve = (
            result.error_count == 0
            and run.has_samples
            and run.all_samples_have_indexes
        )
        if can_approve:
            run.validation_approved = True
            run.touch(reset_validation=False, updated_by=_get_username(req))
            run_repo.save(run)

        return ValidationApprovalBar(run, result)

    @app.post("/runs/{run_id}/validation/unapprove")
    def unapprove_validation(req, run_id: str):
        """Revoke validation approval for a run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        run.validation_approved = False
        run.touch(reset_validation=False, updated_by=_get_username(req))
        run_repo.save(run)

        result = _validate_run(run)
        return ValidationApprovalBar(run, result)
