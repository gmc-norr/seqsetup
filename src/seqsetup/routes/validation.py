"""Validation routes for index collision checking."""

from fasthtml.common import *
from starlette.responses import Response

from ..components.validation_panel import (
    LaneHeatmapContent,
    ValidationApprovalBar,
    ValidationErrorList,
    ValidationPage,
    ValidationTabs,
)
from ..context import AppContext
from ..services.validation import ValidationService
from .utils import get_username


def register(app, rt, ctx: AppContext):
    """Register validation routes."""

    def _validate_run(run):
        """Run validation with profile repos if available."""
        return ValidationService.validate_run(
            run,
            test_profile_repo=ctx.test_profile_repo,
            app_profile_repo=ctx.app_profile_repo,
            instrument_config=ctx.instrument_config,
        )

    @rt("/runs/{run_id}/validation")
    def validation_page(req, run_id: str):
        """Display the full validation page for a run."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return Response("Run not found", status_code=404)

        user = req.scope.get("auth")
        result = _validate_run(run)
        return ValidationPage(run, user, result=result)

    @rt("/runs/{run_id}/validation/tab/{tab}")
    def get_validation_tab(run_id: str, tab: str, type: str = "i7"):
        """Get validation tab content (issues, heatmaps, colorbalance, darkcycles)."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Div(P("Run not found"), cls="error")

        result = _validate_run(run)
        kwargs = {"index_type": type} if tab == "heatmaps" else {}
        return ValidationTabs(run_id, result, active_tab=tab, **kwargs)

    @rt("/runs/{run_id}/validation/errors")
    def get_validation_errors(run_id: str):
        """Get just the validation errors (for quick refresh)."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return Div(P("Run not found"), cls="error")

        result = _validate_run(run)
        return ValidationErrorList(result)

    @rt("/runs/{run_id}/validation/heatmap")
    def get_heatmap(run_id: str, lane: int = 1, type: str = "i7"):
        """Get heatmap for specific lane and index type (legacy endpoint)."""
        if type not in ("i7", "i5"):
            type = "i7"
        run = ctx.run_repo.get_by_id(run_id)

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
        run = ctx.run_repo.get_by_id(run_id)
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
            run.touch(reset_validation=False, updated_by=get_username(req))
            ctx.run_repo.save(run)

        return ValidationApprovalBar(run, result)

    @app.post("/runs/{run_id}/validation/unapprove")
    def unapprove_validation(req, run_id: str):
        """Revoke validation approval for a run."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        run.validation_approved = False
        run.touch(reset_validation=False, updated_by=get_username(req))
        ctx.run_repo.save(run)

        result = _validate_run(run)
        return ValidationApprovalBar(run, result)
