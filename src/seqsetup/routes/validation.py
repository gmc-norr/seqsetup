"""Validation routes — collision checking, heatmaps, approval.

Routes migrated to Starlette + Jinja2 app shell. The validation FT
subtree (heatmaps, color balance, dark cycles, issue list) is still
rendered by Python FT components from ``components/validation/`` via
the transitional ``ft_response`` / ``ft_page_response`` helpers. A
later cleanup PR converts those to Jinja2 templates.
"""

from fasthtml.common import A, Div, H2, P
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..components.validation import (
    LaneHeatmapContent,
    ValidationApprovalBar,
    ValidationErrorList,
    ValidationTabs,
)
from ..context import AppContext
from ..models.sequencing_run import RunStatus
from ..services.audit_log import audit
from ..services.validation import ValidationService
from ..templating import ft_page_response, ft_response
from .utils import get_username


def register(app, ctx: AppContext) -> None:
    """Register validation routes on the parent Starlette app."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"validation.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def _validate_run(run):
        return ValidationService.validate_run(
            run,
            test_profile_repo=ctx.test_profile_repo,
            app_profile_repo=ctx.app_profile_repo,
            instrument_config=ctx.instrument_config,
        )

    def _validation_page_content(run, result):
        """Build the inner FT subtree for the validation page (no shell)."""
        return Div(
            Div(
                A("Back to Run", href=f"/runs/{run.id}", cls="btn btn-secondary btn-small"),
                H2(f"Validation: {run.run_name or 'Unnamed Run'}"),
                cls="validation-page-header",
            ),
            ValidationApprovalBar(run, result),
            ValidationTabs(run.id, result),
            cls="validation-page",
        )

    def validation_page(request: Request) -> Response:
        """GET /runs/{run_id}/validation — full validation page."""
        run_id = request.path_params["run_id"]
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        result = _validate_run(run)
        return ft_page_response(
            request,
            _validation_page_content(run, result),
            page_title=f"Validation - {run.run_name or run.id}",
            active_route=f"/runs/{run.id}",
        )

    def get_validation_tab(request: Request) -> Response:
        """GET /runs/{run_id}/validation/tab/{tab} — HTMX swap for tab content."""
        run_id = request.path_params["run_id"]
        tab = request.path_params["tab"]
        index_type = request.query_params.get("type", "i7")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return ft_response(Div(P("Run not found"), cls="error"), status_code=404)

        result = _validate_run(run)
        kwargs = {"index_type": index_type} if tab == "heatmaps" else {}
        return ft_response(ValidationTabs(run_id, result, active_tab=tab, **kwargs))

    def get_validation_errors(request: Request) -> Response:
        """GET /runs/{run_id}/validation/errors — error-list refresh."""
        run_id = request.path_params["run_id"]
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return ft_response(Div(P("Run not found"), cls="error"), status_code=404)

        result = _validate_run(run)
        return ft_response(ValidationErrorList(result))

    def get_heatmap(request: Request) -> Response:
        """GET /runs/{run_id}/validation/heatmap — legacy single-heatmap endpoint."""
        run_id = request.path_params["run_id"]
        try:
            lane = int(request.query_params.get("lane", "1"))
        except ValueError:
            lane = 1
        index_type = request.query_params.get("type", "i7")
        if index_type not in ("i7", "i5"):
            index_type = "i7"

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return ft_response(Div(P("Run not found"), cls="error"), status_code=404)

        result = _validate_run(run)
        matrix = result.distance_matrices.get(lane)
        if matrix and len(matrix.sample_names) >= 2:
            return ft_response(LaneHeatmapContent(run_id, lane, matrix, index_type=index_type))
        return ft_response(Div(P(f"No samples in lane {lane}"), cls="info"))

    def approve_validation(request: Request) -> Response:
        """POST /runs/{run_id}/validation/approve."""
        run_id = request.path_params["run_id"]
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)
        if run.status != RunStatus.DRAFT:
            return Response("Validation can only be approved on draft runs", status_code=400)

        result = _validate_run(run)
        can_approve = (
            result.error_count == 0
            and run.has_samples
            and run.all_samples_have_indexes
        )
        if can_approve:
            run.validation_approved = True
            run.touch(reset_validation=False, updated_by=get_username(request))
            ctx.run_repo.save(run)
            audit("validation.approved", actor=get_username(request), target=run_id)
        else:
            audit(
                "validation.approve.denied",
                actor=get_username(request),
                target=run_id,
                outcome="denied",
                error_count=result.error_count,
                has_samples=run.has_samples,
                all_samples_have_indexes=run.all_samples_have_indexes,
            )

        return ft_response(ValidationApprovalBar(run, result))

    def unapprove_validation(request: Request) -> Response:
        """POST /runs/{run_id}/validation/unapprove."""
        run_id = request.path_params["run_id"]
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)
        if run.status == RunStatus.ARCHIVED:
            return Response("Cannot modify archived runs", status_code=400)

        run.validation_approved = False
        run.touch(reset_validation=False, updated_by=get_username(request))
        ctx.run_repo.save(run)
        audit("validation.unapproved", actor=get_username(request), target=run_id)

        result = _validate_run(run)
        return ft_response(ValidationApprovalBar(run, result))

    app.routes.append(Route("/runs/{run_id}/validation", validation_page, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/validation/tab/{tab}", get_validation_tab, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/validation/errors", get_validation_errors, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/validation/heatmap", get_heatmap, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/validation/approve", approve_validation, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/validation/unapprove", unapprove_validation, methods=["POST"]))
