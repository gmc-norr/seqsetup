"""Validation page, approval bar, and tabbed layout."""

from typing import Optional

from fasthtml.common import *

from ...models.sequencing_run import SequencingRun
from ...models.user import User
from ...models.validation import ValidationResult
from ...services.validation import ValidationService
from ..layout import AppShell
from .issues import IssuesTabContent
from .heatmaps import HeatmapsTabContent
from .color_balance import ColorBalanceTabContent, DarkCyclesTabContent


def ValidationPage(run: SequencingRun, user: Optional[User] = None, active_tab: str = "issues", result: Optional[ValidationResult] = None):
    """
    Full validation page wrapped in AppShell with tabbed layout.

    Args:
        run: Sequencing run to validate
        user: Current authenticated user
        active_tab: "issues", "heatmaps", "colorbalance", or "darkcycles"
        result: Pre-computed validation result (if None, runs basic validation without profile checks)
    """
    if result is None:
        result = ValidationService.validate_run(run)

    return AppShell(
        user=user,
        active_route=f"/runs/{run.id}",
        content=Div(
            Div(
                A(
                    "Back to Run",
                    href=f"/runs/{run.id}",
                    cls="btn btn-secondary btn-small",
                ),
                H2(f"Validation: {run.run_name or 'Unnamed Run'}"),
                cls="validation-page-header",
            ),
            ValidationApprovalBar(run, result),
            ValidationTabs(run.id, result, active_tab),
            cls="validation-page",
        ),
        title=f"Validation - {run.run_name or run.id}",
    )


def ValidationApprovalBar(run: SequencingRun, result: ValidationResult):
    """Approval bar showing validation status and approve/unapprove button."""
    can_approve = (
        result.error_count == 0
        and run.has_samples
        and run.all_samples_have_indexes
    )

    if run.validation_approved:
        return Div(
            Span("Validation approved", cls="status-ok", style="font-weight:600;"),
            Button(
                "Revoke Approval",
                hx_post=f"/runs/{run.id}/validation/unapprove",
                hx_target="#validation-approval-bar",
                hx_swap="outerHTML",
                cls="btn btn-secondary btn-small",
                style="margin-left:0.75rem;",
            ),
            id="validation-approval-bar",
            cls="validation-approval-bar approved",
        )
    elif can_approve:
        return Div(
            Span("Validation passed", cls="status-ok"),
            Button(
                "Approve Validation",
                hx_post=f"/runs/{run.id}/validation/approve",
                hx_target="#validation-approval-bar",
                hx_swap="outerHTML",
                cls="btn btn-primary btn-small",
                style="margin-left:0.75rem;",
            ),
            id="validation-approval-bar",
            cls="validation-approval-bar",
        )
    else:
        return Div(
            Span("Validation has issues \u2014 resolve before approving", cls="status-error"),
            id="validation-approval-bar",
            cls="validation-approval-bar",
        )


def ValidationTabs(run_id: str, result: ValidationResult, active_tab: str = "issues", index_type: str = "i7"):
    """
    Tabbed layout with Issues, Heatmaps, Color Balance, and Dark Cycles tabs.

    Args:
        run_id: Run ID for HTMX requests
        result: Validation result
        active_tab: "issues", "heatmaps", "colorbalance", or "darkcycles"
        index_type: "i7", "i5", or "combined" for heatmaps
    """
    error_count = result.error_count
    warning_count = result.warning_count
    issue_count = error_count + warning_count
    has_matrices = bool(result.distance_matrices)
    has_color_balance = bool(result.color_balance)
    color_balance_issues = result.color_balance_issue_count
    color_balance_enabled = result.color_balance_enabled

    # Determine tab content
    if active_tab == "issues":
        tab_content = IssuesTabContent(result)
    elif active_tab == "heatmaps":
        tab_content = HeatmapsTabContent(run_id, result, index_type)
    elif active_tab == "colorbalance":
        tab_content = ColorBalanceTabContent(run_id, result)
    elif active_tab == "darkcycles":
        tab_content = DarkCyclesTabContent(run_id, result)
    else:
        tab_content = IssuesTabContent(result)

    # Color balance tab button - only enabled for supported instruments
    if color_balance_enabled and has_color_balance:
        color_balance_button = Button(
            f"Color Balance ({color_balance_issues})" if color_balance_issues > 0 else "Color Balance",
            cls="tab-button active" if active_tab == "colorbalance" else "tab-button",
            hx_get=f"/runs/{run_id}/validation/tab/colorbalance",
            hx_target="#validation-tabs",
            hx_swap="outerHTML",
        )
    elif not color_balance_enabled:
        color_balance_button = Button(
            "Color Balance",
            cls="tab-button disabled",
            disabled=True,
            title="Not applicable for this instrument",
        )
    else:
        color_balance_button = Button(
            "Color Balance",
            cls="tab-button disabled",
            disabled=True,
            title="No indexed samples",
        )

    # Dark Cycles tab button - only for 2-color instruments
    dark_cycle_count = len(result.dark_cycle_errors)
    if color_balance_enabled:
        dark_cycles_button = Button(
            f"Dark Cycles ({dark_cycle_count})" if dark_cycle_count > 0 else "Dark Cycles",
            cls="tab-button active" if active_tab == "darkcycles" else "tab-button",
            hx_get=f"/runs/{run_id}/validation/tab/darkcycles",
            hx_target="#validation-tabs",
            hx_swap="outerHTML",
        )
    else:
        dark_cycles_button = Button(
            "Dark Cycles",
            cls="tab-button disabled",
            disabled=True,
            title="Not applicable for this instrument",
        )

    return Div(
        # Tab buttons
        Div(
            Button(
                f"Issues ({issue_count})" if issue_count > 0 else "Issues",
                cls="tab-button active" if active_tab == "issues" else "tab-button",
                hx_get=f"/runs/{run_id}/validation/tab/issues",
                hx_target="#validation-tabs",
                hx_swap="outerHTML",
            ),
            Button(
                "Heatmaps",
                cls="tab-button active" if active_tab == "heatmaps" else "tab-button",
                hx_get=f"/runs/{run_id}/validation/tab/heatmaps?type={index_type}",
                hx_target="#validation-tabs",
                hx_swap="outerHTML",
            ) if has_matrices else Button(
                "Heatmaps",
                cls="tab-button disabled",
                disabled=True,
                title="No lanes with multiple indexed samples",
            ),
            color_balance_button,
            dark_cycles_button,
            cls="tab-buttons",
        ),
        # Tab content
        Div(
            tab_content,
            id="validation-tab-content",
            cls="tab-content active",
        ),
        cls="validation-tabs",
        id="validation-tabs",
    )
