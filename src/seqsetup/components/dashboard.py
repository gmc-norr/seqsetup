"""Dashboard components for displaying runs list."""

from fasthtml.common import *

from ..models.sequencing_run import RunStatus, SequencingRun


def DashboardContent(runs: list[SequencingRun], active_tab: str = "draft"):
    """
    Main dashboard content with tabbed run lists.

    Args:
        runs: List of all sequencing runs
        active_tab: "draft", "ready", or "archived"
    """
    if not runs:
        return EmptyDashboard()

    # Count runs per status
    counts = {
        "draft": sum(1 for r in runs if r.status == RunStatus.DRAFT),
        "ready": sum(1 for r in runs if r.status == RunStatus.READY),
        "archived": sum(1 for r in runs if r.status == RunStatus.ARCHIVED),
    }

    # Get runs for the active tab
    status_map = {
        "draft": RunStatus.DRAFT,
        "ready": RunStatus.READY,
        "archived": RunStatus.ARCHIVED,
    }
    target_status = status_map.get(active_tab, RunStatus.DRAFT)
    tab_runs = sorted(
        [r for r in runs if r.status == target_status],
        key=lambda r: r.updated_at, reverse=True,
    )

    return Div(
        DashboardTabs(counts, active_tab),
        Div(
            RunList(tab_runs),
            id="dashboard-tab-content",
            cls="dashboard-tab-content",
        ),
        cls="dashboard-content",
        id="dashboard",
    )


def DashboardTabs(counts: dict[str, int], active_tab: str = "draft"):
    """Tab buttons with counts for each status."""
    tabs = [
        ("draft", "Draft", counts.get("draft", 0)),
        ("ready", "Ready", counts.get("ready", 0)),
        ("archived", "Archived", counts.get("archived", 0)),
    ]

    return Div(
        *[
            Button(
                f"{label} ({count})",
                cls="tab-button active" if key == active_tab else "tab-button",
                hx_get=f"/dashboard/tab/{key}",
                hx_target="#dashboard",
                hx_swap="outerHTML",
            )
            for key, label, count in tabs
        ],
        cls="tab-buttons dashboard-tabs",
    )


def EmptyDashboard():
    """Empty state when no runs exist."""
    return Div(
        Div(
            H2("No Runs Yet"),
            P("Get started by creating your first run."),
            A(
                "+ New Run",
                href="/runs/new",
                cls="btn btn-primary",
            ),
            cls="empty-state-content",
        ),
        cls="empty-state",
    )


def RunList(runs: list[SequencingRun]):
    """Run list table for the active tab."""
    if not runs:
        return P("No runs", cls="run-list-empty")

    return Div(
        # Table header
        Div(
            Span("Name", cls="rl-col rl-name"),
            Span("Platform", cls="rl-col rl-platform"),
            Span("Flowcell", cls="rl-col rl-flowcell"),
            Span("Samples", cls="rl-col rl-samples"),
            Span("Created by", cls="rl-col rl-user"),
            Span("Modified by", cls="rl-col rl-user"),
            Span("Updated", cls="rl-col rl-updated"),
            Span("", cls="rl-col rl-actions"),
            cls="run-list-row run-list-header-row",
        ),
        *[RunListItem(run) for run in runs],
        cls="run-list",
    )


def RunListItem(run: SequencingRun):
    """A single row in a run list."""
    display_name = run.run_name or "Untitled Run"
    updated_str = run.updated_at.strftime("%Y-%m-%d %H:%M")
    is_archived = run.status == RunStatus.ARCHIVED

    actions = [A("Edit", href=f"/runs/{run.id}", cls="btn btn-secondary btn-small")]
    if not is_archived:
        actions.append(Button(
            "Archive",
            hx_post=f"/runs/{run.id}/archive",
            hx_target="#dashboard",
            hx_swap="outerHTML",
            hx_confirm="Archive this run?",
            cls="btn btn-warning btn-small",
        ))
    if is_archived:
        actions.append(Button(
            "Delete",
            hx_delete=f"/runs/{run.id}",
            hx_target="#dashboard",
            hx_swap="outerHTML",
            hx_confirm="Are you sure you want to delete this run?",
            cls="btn btn-danger btn-small",
        ))

    return Div(
        A(display_name, href=f"/runs/{run.id}", cls="rl-col rl-name rl-link"),
        Span(run.instrument_platform.value, cls="rl-col rl-platform"),
        Span(run.flowcell_type or "—", cls="rl-col rl-flowcell"),
        Span(str(len(run.samples)), cls="rl-col rl-samples"),
        Span(run.created_by or "—", cls="rl-col rl-user"),
        Span(run.updated_by or "—", cls="rl-col rl-user"),
        Span(updated_str, cls="rl-col rl-updated"),
        Div(*actions, cls="rl-col rl-actions"),
        cls="run-list-row run-list-item",
        id=f"run-item-{run.id}",
    )
