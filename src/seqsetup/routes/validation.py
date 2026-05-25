"""Validation routes — page render + approve/unapprove.

Migrated to APIRouter. The four tab contents (Issues, Heatmaps,
Color Balance, Dark Cycles) are pre-rendered to HTML strings by
Jinja2 partial templates and injected into the page template via
|safe. Alpine x-shows the active tab — no network round-trip per tab.

The HTMX tab-swap endpoint /validation/tab/{tab} is GONE; Alpine
replaces it. The /validation/heatmap endpoint (single-lane FT
fragment for index-type switching) is also GONE — Alpine state now
controls index-type switching client-side with all three matrices
pre-rendered into the page.

Validation services remain READ-ONLY. Approve/unapprove mutate
run.validation_approved through the same touch+save pattern as
before; both audit events preserved verbatim.
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..models.sequencing_run import RunStatus
from ..models.validation import ColorBalanceStatus
from ..services.audit_log import audit
from ..services.validation import ValidationService
from ..templating import render, templates
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


# ---------------------------------------------------------------------------
# Per-cell data builders for Jinja2 templates
# ---------------------------------------------------------------------------

def _build_heatmap_lanes(result):
    """Build the lanes list for _heatmaps_tab.html."""
    lanes = []
    for lane in sorted(result.distance_matrices.keys()):
        matrix = result.distance_matrices[lane]
        if len(matrix.sample_names) < 2:
            continue
        n = len(matrix.sample_names)
        names = [name[:8] + ".." if len(name) > 8 else name for name in matrix.sample_names]
        full_names = list(matrix.sample_names)

        def _cells_for(distances):
            rows = []
            for i in range(n):
                row = []
                for j in range(n):
                    dist = distances[i][j]
                    if i == j:
                        row.append({"content": "-", "class": "heatmap-cell diagonal", "title": "Distance: None"})
                    elif dist is None:
                        row.append({"content": "N/A", "class": "heatmap-cell no-data", "title": "Distance: None"})
                    else:
                        dist_class = min(dist, 10)
                        row.append({
                            "content": str(dist),
                            "class": f"heatmap-cell dist-{dist_class}",
                            "title": f"Distance: {dist}",
                        })
                rows.append(row)
            return rows

        lanes.append({
            "lane": lane,
            "names": names,
            "full_names": full_names,
            "cells": {
                "i7": _cells_for(matrix.i7_distances),
                "i5": _cells_for(matrix.i5_distances),
                "combined": _cells_for(matrix.combined_distances),
            },
        })
    return lanes


def _channel_class(percent: float) -> str:
    """CSS class for a channel percentage value."""
    if percent >= 50:
        return "channel-high"
    elif percent >= 25:
        return "channel-medium"
    elif percent > 0:
        return "channel-low"
    return "channel-zero"


def _build_color_balance_ctx(result):
    """Build context dict for _color_balance_tab.html."""
    if not result.color_balance_enabled:
        return {
            "color_balance_enabled": False,
            "color_balance_desc": None,
            "legend": None,
            "lanes": [],
        }

    if not result.color_balance:
        return {
            "color_balance_enabled": True,
            "color_balance_desc": None,
            "legend": None,
            "lanes": [],
        }

    cc = result.channel_config
    if cc:
        ch1_name = cc["channel1_name"]
        ch1_bases = ", ".join(cc["channel1_bases"])
        ch2_name = cc["channel2_name"]
        ch2_bases = ", ".join(cc["channel2_bases"])
        dark = cc.get("dark_base", "G")
        desc_text = (
            f"This instrument uses {ch1_name} ({ch1_bases}) and {ch2_name} ({ch2_bases}) channels. "
            f"{dark} bases are dark (neither channel). Good color balance requires signals "
            f"in both channels at each position."
        )
        legend = {
            "ch1_name": ch1_name,
            "ch1_bases": "+".join(cc["channel1_bases"]),
            "ch2_name": ch2_name,
            "ch2_bases": "+".join(cc["channel2_bases"]),
        }
    else:
        desc_text = (
            "2-color chemistry requires signals in both channels at each position. "
            "Good color balance ensures accurate base calling."
        )
        legend = {
            "ch1_name": "Channel 1",
            "ch1_bases": "A+C",
            "ch2_name": "Channel 2",
            "ch2_bases": "C+T",
        }

    lanes = []
    for lane in sorted(result.color_balance.keys()):
        lb = result.color_balance[lane]
        tables = []

        for index_balance in [lb.i7_balance, lb.i5_balance]:
            if not index_balance or not index_balance.positions:
                continue
            first_pos = index_balance.positions[0]
            rows = []
            for pos in index_balance.positions:
                status_cls = f"status-{pos.status.value}"
                if pos.status == ColorBalanceStatus.OK:
                    status_icon = "✓"
                elif pos.status == ColorBalanceStatus.WARNING:
                    status_icon = "⚠"
                else:
                    status_icon = "✗"
                rows.append({
                    "position": pos.position,
                    "a_count": pos.a_count,
                    "c_count": pos.c_count,
                    "g_count": pos.g_count,
                    "t_count": pos.t_count,
                    "channel1_pct": f"{pos.channel1_percent:.0f}%",
                    "channel1_class": _channel_class(pos.channel1_percent),
                    "channel2_pct": f"{pos.channel2_percent:.0f}%",
                    "channel2_class": _channel_class(pos.channel2_percent),
                    "status_icon": status_icon,
                    "status_cls": status_cls,
                    "row_cls": f"cb-row {status_cls}",
                })
            tables.append({
                "index_type": index_balance.index_type,
                "ch1_name": first_pos.channel1_name,
                "ch2_name": first_pos.channel2_name,
                "rows": rows,
            })

        lanes.append({
            "lane": lb.lane,
            "sample_count": lb.sample_count,
            "has_issues": lb.has_issues,
            "tables": tables,
        })

    return {
        "color_balance_enabled": True,
        "color_balance_desc": desc_text,
        "legend": legend,
        "lanes": lanes,
    }


def _build_dark_cycles_ctx(result):
    """Build context dict for _dark_cycles_tab.html."""
    if not result.color_balance_enabled:
        return {
            "color_balance_enabled": False,
            "desc_text": None,
            "summary": [],
            "dark_base": None,
            "legend_dark_base": None,
            "rows": [],
        }

    samples = result.dark_cycle_samples
    if not samples:
        return {
            "color_balance_enabled": True,
            "desc_text": None,
            "summary": [],
            "dark_base": None,
            "legend_dark_base": None,
            "rows": [],
        }

    dark_base = samples[0].dark_base
    cc = result.channel_config
    if cc:
        desc_text = (
            f"Dark base for this chemistry: {dark_base} (no signal in either channel). "
            f"Two consecutive dark bases at the start of an index prevent reliable detection "
            f"of the index read start. One dark base in the first two positions is acceptable."
        )
    else:
        desc_text = (
            f"Dark base: {dark_base}. Two consecutive dark bases at the start of an index "
            f"prevent reliable detection of the index read start."
        )

    error_count = sum(1 for s in samples if s.i7_leading_dark >= 2 or s.i5_leading_dark >= 2)
    warning_count = sum(
        1 for s in samples
        if (s.i7_leading_dark == 1 or s.i5_leading_dark == 1)
        and s.i7_leading_dark < 2 and s.i5_leading_dark < 2
    )

    summary = []
    if error_count > 0:
        summary.append({"text": f"{error_count} error(s)", "cls": "dc-summary-error"})
    if warning_count > 0:
        summary.append({"text": f"{warning_count} warning(s)", "cls": "dc-summary-warning"})
    if not summary:
        summary.append({"text": "No dark cycle issues", "cls": "dc-summary-ok"})

    def _viz(sequence):
        if not sequence:
            return None
        bases = []
        for i, base in enumerate(sequence):
            is_dark = base.upper() == dark_base.upper()
            is_leading = i < 2
            cls_parts = ["dc-base"]
            if is_dark:
                cls_parts.append("dc-dark")
            if is_leading:
                cls_parts.append("dc-leading")
            if is_dark and is_leading:
                cls_parts.append("dc-dark-leading")
            bases.append({"base": base.upper(), "cls": " ".join(cls_parts)})
        return bases

    def _status(leading_dark):
        if leading_dark >= 2:
            return "Error — two dark", "dc-status-error"
        elif leading_dark == 1:
            return "OK — one dark", "dc-status-warning"
        return "OK", "dc-status-ok"

    rows = []
    for sample in samples:
        has_error = sample.i7_leading_dark >= 2 or sample.i5_leading_dark >= 2
        has_warning = (
            not has_error
            and (sample.i7_leading_dark == 1 or sample.i5_leading_dark == 1)
        )
        row_cls = "dc-row"
        if has_error:
            row_cls += " dc-row-error"
        elif has_warning:
            row_cls += " dc-row-warning"

        i7_viz = _viz(sample.i7_sequence) if sample.i7_sequence else None
        i7_status_text, i7_status_cls = _status(sample.i7_leading_dark) if sample.i7_sequence else (None, None)

        i5_viz = _viz(sample.i5_read_sequence) if sample.i5_sequence else None
        i5_status_text, i5_status_cls = _status(sample.i5_leading_dark) if sample.i5_sequence else (None, None)

        rows.append({
            "sample_name": sample.sample_name,
            "row_cls": row_cls,
            "i7_viz": i7_viz,
            "i7_status_text": i7_status_text,
            "i7_status_cls": i7_status_cls,
            "i5_viz": i5_viz,
            "i5_status_text": i5_status_text,
            "i5_status_cls": i5_status_cls,
        })

    return {
        "color_balance_enabled": True,
        "desc_text": desc_text,
        "summary": summary,
        "dark_base": dark_base,
        "legend_dark_base": dark_base,
        "rows": rows,
    }


def _render_tab_contents(run_id, result):
    """Pre-render each tab's body to an HTML string for Jinja2 |safe interpolation."""
    env = templates.env
    return {
        "issues_html": env.get_template("validation/_issues_tab.html").render(result=result),
        "heatmaps_html": env.get_template("validation/_heatmaps_tab.html").render(
            lanes=_build_heatmap_lanes(result),
        ),
        "color_balance_html": env.get_template("validation/_color_balance_tab.html").render(
            **_build_color_balance_ctx(result),
        ),
        "dark_cycles_html": env.get_template("validation/_dark_cycles_tab.html").render(
            **_build_dark_cycles_ctx(result),
        ),
    }


def _approval_state(run, result) -> dict:
    """Compute the approval-bar state."""
    can_approve = result.error_count == 0
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
    can_approve = result.error_count == 0
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
