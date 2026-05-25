"""Validation routes — page render + approve/unapprove.

Migrated to APIRouter. The four tab contents (Issues, Heatmaps,
Color Balance, Dark Cycles) are pre-rendered to HTML strings by
the existing FT components and injected into the Jinja2 page
template via |safe. Alpine then x-shows the active tab — no
network round-trip per tab.

The HTMX tab-swap endpoint /validation/tab/{tab} is GONE; Alpine
replaces it. The heatmap and errors refresh endpoints stay as
narrower fallbacks (index-type switching within the heatmap tab,
errors-list refresh after dismissals).

Validation services remain READ-ONLY. Approve/unapprove mutate
run.validation_approved through the same touch+save pattern as
before; both audit events preserved verbatim.
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..models.sequencing_run import RunStatus
from ..services.audit_log import audit
from ..services.validation import ValidationService
from ..templating import ft_response, render
from .dependencies import get_ctx
from .utils import get_username


router = APIRouter(tags=["validation"])


def _validate_run(run, ctx):
    return ValidationService.validate_run(
        run,
        test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config,
    )


def _render_tab_contents(run_id, result, index_type="i7"):
    """Pre-render each tab's FT body to an HTML string.

    Returns a dict {issues_html, heatmaps_html, color_balance_html,
    dark_cycles_html} suitable for Jinja2 |safe interpolation.
    """
    from ..components.validation import (
        ColorBalanceTabContent,
        DarkCyclesTabContent,
        HeatmapsTabContent,
    )
    from ..templating import templates

    def _to_str(ft):
        # Render the FT component to its HTML string.
        from fasthtml.common import to_xml
        return to_xml(ft)

    return {
        "issues_html": templates.env.get_template("validation/_issues_tab.html").render(result=result),
        "heatmaps_html": _to_str(HeatmapsTabContent(run_id, result, index_type)),
        "color_balance_html": _to_str(ColorBalanceTabContent(run_id, result)),
        "dark_cycles_html": _to_str(DarkCyclesTabContent(run_id, result)),
    }


def _approval_state(run, result) -> dict:
    """Compute the approval-bar state."""
    can_approve = (
        result.error_count == 0
        and run.has_samples
        and run.all_samples_have_indexes
    )
    return {
        "run": run,
        "result": result,
        "can_approve": can_approve,
    }


@router.get("/runs/{run_id}/validation", response_class=HTMLResponse)
def validation_page(
    request: Request,
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/validation — full page with all tabs pre-rendered."""
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return Response("Run not found", status_code=404)

    result = _validate_run(run, ctx)
    error_count = result.error_count
    warning_count = result.warning_count
    issue_count = error_count + warning_count
    has_matrices = bool(result.distance_matrices)
    color_balance_enabled = result.color_balance_enabled
    color_balance_issues = result.color_balance_issue_count
    dark_cycle_count = len(result.dark_cycle_errors)

    ctx_dict = {
        "run": run,
        "run_id": run_id,
        "issue_count": issue_count,
        "color_balance_enabled": color_balance_enabled,
        "color_balance_issues": color_balance_issues,
        "dark_cycle_count": dark_cycle_count,
        "has_matrices": has_matrices,
        "has_color_balance": bool(result.color_balance),
        **_approval_state(run, result),
        **_render_tab_contents(run_id, result),
    }
    return render(request, "validation/page.html", ctx_dict)


@router.get("/runs/{run_id}/validation/heatmap", response_class=HTMLResponse)
def get_heatmap(
    request: Request,
    run_id: str,
    lane: int = 1,
    ctx: AppContext = Depends(get_ctx),
    type: str = "i7",
) -> Response:
    """GET /runs/{run_id}/validation/heatmap — single-lane heatmap refresh.

    Used when the user switches index-type (i7/i5) inside the heatmap
    tab. Keeps the existing FT renderer.
    """
    from fasthtml.common import Div, P
    from ..components.validation import LaneHeatmapContent

    if type not in ("i7", "i5"):
        type = "i7"

    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return ft_response(Div(P("Run not found"), cls="error"), status_code=404)

    result = _validate_run(run, ctx)
    matrix = result.distance_matrices.get(lane)
    if matrix and len(matrix.sample_names) >= 2:
        return ft_response(LaneHeatmapContent(run_id, lane, matrix, index_type=type))
    return ft_response(Div(P(f"No samples in lane {lane}"), cls="info"))


@router.get("/runs/{run_id}/validation/errors", response_class=HTMLResponse)
def get_validation_errors(
    request: Request,
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/validation/errors — errors-list refresh."""
    from fasthtml.common import Div, P

    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return ft_response(Div(P("Run not found"), cls="error"), status_code=404)
    result = _validate_run(run, ctx)
    return render(request, "validation/_error_list.html", {"result": result})


@router.post("/runs/{run_id}/validation/approve", response_class=HTMLResponse)
def approve_validation(
    request: Request,
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/validation/approve — approve validation if eligible.

    Returns the {% block approval_bar %} fragment from validation/page.html
    so HTMX outerHTML-swaps into #validation-approval-bar.
    """
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return Response("Run not found", status_code=404)
    if run.status != RunStatus.DRAFT:
        return Response("Validation can only be approved on draft runs", status_code=400)

    result = _validate_run(run, ctx)
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
    return render(
        request,
        "validation/page.html",
        {"run_id": run_id, **_approval_state(run, result)},
        block_name="approval_bar",
    )


@router.post("/runs/{run_id}/validation/unapprove", response_class=HTMLResponse)
def unapprove_validation(
    request: Request,
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/validation/unapprove — revoke approval."""
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return Response("Run not found", status_code=404)
    if run.status == RunStatus.ARCHIVED:
        return Response("Cannot modify archived runs", status_code=400)

    run.validation_approved = False
    run.touch(reset_validation=False, updated_by=get_username(request))
    ctx.run_repo.save(run)
    audit("validation.unapproved", actor=get_username(request), target=run_id)

    result = _validate_run(run, ctx)
    return render(
        request,
        "validation/page.html",
        {"run_id": run_id, **_approval_state(run, result)},
        block_name="approval_bar",
    )
