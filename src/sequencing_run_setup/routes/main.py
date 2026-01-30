"""Edit run page routes."""

from fasthtml.common import *
from starlette.responses import RedirectResponse

from ..components.layout import AppShell
from ..models.sequencing_run import RunStatus
from ..services.validation import ValidationService


def register(app, rt, get_run_repo, get_index_kit_repo):
    """Register main page routes."""

    @rt("/runs/{run_id}")
    def edit_run(req, run_id: str):
        """Render the edit run page with config above samples."""
        run_repo = get_run_repo()
        index_kit_repo = get_index_kit_repo()
        user = req.scope.get("auth")

        run = run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

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
                SampleTableSectionForRun(run, index_kit_repo.list_all()),
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


def RunStatusBar(run):
    """Status bar showing current run status and transition buttons."""
    status_labels = {
        RunStatus.DRAFT: ("Draft", "status-draft"),
        RunStatus.READY: ("Ready", "status-ready"),
        RunStatus.ARCHIVED: ("Archived", "status-archived"),
    }
    label, badge_cls = status_labels.get(run.status, ("Draft", "status-draft"))

    actions = []
    if run.status == RunStatus.DRAFT:
        if run.validation_approved:
            actions.append(Form(
                Button("Mark Ready", type="submit", cls="btn btn-primary btn-small"),
                hx_post=f"/runs/{run.id}/status/ready",
                hx_target="#run-status-bar",
                hx_swap="outerHTML",
            ))
        else:
            actions.append(Button(
                "Mark Ready",
                cls="btn btn-primary btn-small",
                disabled=True,
                title="Validation must be approved first",
            ))
    elif run.status == RunStatus.READY:
        actions.append(Form(
            Button("Archive", type="submit", cls="btn btn-secondary btn-small"),
            hx_post=f"/runs/{run.id}/status/archived",
            hx_target="#run-status-bar",
            hx_swap="outerHTML",
        ))
    elif run.status == RunStatus.ARCHIVED:
        actions.append(Form(
            Button("Reset to Draft", type="submit", cls="btn btn-secondary btn-small"),
            hx_post=f"/runs/{run.id}/status/draft",
            hx_target="#run-status-bar",
            hx_swap="outerHTML",
        ))

    return Div(
        Div(
            Span("Status: ", cls="status-label"),
            Span(label, cls=f"run-status-badge {badge_cls}"),
            cls="run-status-info",
        ),
        Div(*actions, cls="run-status-actions"),
        cls="run-status-bar",
        id="run-status-bar",
    )


def SampleTableSectionForRun(run, index_kits=None):
    """Sample table section with run_id in paths."""
    from ..components.wizard import SampleTableWizard
    from ..data.instruments import get_lanes_for_flowcell

    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)

    return Div(
        Div(
            A(
                "+ Add Samples",
                href=f"/runs/{run.id}/samples/add/step/1",
                cls="btn btn-primary btn-small",
            ),
            cls="add-samples-btn",
        ),
        SampleTableWizard(run, show_drop_zones=True, index_kits=index_kits, num_lanes=num_lanes),
        id="sample-section",
    )


def RunConfigPanelHorizontal(run):
    """Run config panel with horizontal layout for edit page (read-only)."""
    from ..components.run_config import (
        CycleConfigDisplay,
        InstrumentConfigDisplay,
        RunNameDisplay,
    )

    # Format metadata
    created_at_str = run.created_at.strftime("%Y-%m-%d %H:%M") if run.created_at else "—"
    updated_at_str = run.updated_at.strftime("%Y-%m-%d %H:%M") if run.updated_at else "—"
    created_by_str = run.created_by or "—"

    return Div(
        Div(
            # Left column - Run details
            Div(
                Fieldset(
                    Legend("Details"),
                    RunNameDisplay(run),
                    # Metadata fields under Run Name
                    Div(
                        Span("UUID: ", cls="config-label"),
                        Span(run.id, cls="config-value uuid-value", title=run.id),
                        cls="config-item",
                    ),
                    Div(
                        Span("Created by: ", cls="config-label"),
                        Span(created_by_str, cls="config-value"),
                        cls="config-item",
                    ),
                    Div(
                        Span("Created: ", cls="config-label"),
                        Span(created_at_str, cls="config-value"),
                        cls="config-item",
                    ),
                    Div(
                        Span("Updated: ", cls="config-label"),
                        Span(updated_at_str, cls="config-value"),
                        cls="config-item",
                    ),
                    cls="config-panel details-display",
                ),
                cls="config-column",
            ),
            # Middle column - Instrument settings
            Div(
                InstrumentConfigDisplay(run),
                cls="config-column",
            ),
            # Right column - Cycle config
            Div(
                CycleConfigDisplay(run),
                cls="config-column",
            ),
            cls="config-columns",
        ),
        cls="run-config-horizontal",
        id="run-config-panel",
    )


def TopBarForRun(run):
    """Top bar containing Validate and Export panels side by side."""
    return Div(
        Div(
            Div(
                ValidatePanelForRun(run),
                cls="config-column",
            ),
            Div(
                ExportPanelForRun(run),
                cls="config-column",
            ),
            cls="top-bar-columns",
        ),
        cls="run-config-horizontal",
    )


def ValidatePanelForRun(run):
    """Validation panel showing run validation status with link to details."""
    # Run full validation
    result = ValidationService.validate_run(run)

    # Count issues
    error_count = result.error_count
    color_balance_issues = result.color_balance_issue_count if result.color_balance_enabled else 0

    # Determine overall status
    has_samples = run.has_samples
    all_have_indexes = run.all_samples_have_indexes if has_samples else False
    samples_with_indexes = sum(1 for s in run.samples if s.has_index)

    # Build status items
    status_items = []

    # Samples count
    if has_samples:
        status_items.append(
            Span(f"Samples: {len(run.samples)}", cls="status-ok")
        )
    else:
        status_items.append(
            Span("No samples", cls="status-error")
        )

    # Indexes status
    if has_samples:
        if all_have_indexes:
            status_items.append(
                Span(f"Indexes: {samples_with_indexes}/{len(run.samples)}", cls="status-ok")
            )
        else:
            status_items.append(
                Span(f"Indexes: {samples_with_indexes}/{len(run.samples)}", cls="status-warning")
            )

    # Validation errors (duplicates + collisions)
    if error_count > 0:
        status_items.append(
            Span(f"Errors: {error_count}", cls="status-error")
        )

    # Color balance warnings
    if color_balance_issues > 0:
        status_items.append(
            Span(f"Color balance: {color_balance_issues} lane(s)", cls="status-warning")
        )

    # Validation approval status
    if run.validation_approved:
        status_items.append(
            Span("Approved", cls="status-ok")
        )
    else:
        status_items.append(
            Span("Not approved", cls="status-warning")
        )

    # Overall status class
    if error_count > 0 or not has_samples:
        status_cls = "has-errors"
    elif not all_have_indexes or color_balance_issues > 0:
        status_cls = "has-warnings"
    else:
        status_cls = "ok"

    return Fieldset(
        Legend("Validate"),
        Div(
            Div(
                *status_items,
                cls=f"validate-status-badges {status_cls}",
            ),
            Div(
                A(
                    "Review & Approve",
                    href=f"/runs/{run.id}/validation",
                    cls="validate-details-link",
                ),
                cls="validate-footer",
            ),
            cls="validate-panel-content",
        ),
        cls="config-panel validate-display",
    )


def ExportPanelForRun(run):
    """Export panel with download buttons."""
    # Check if export is allowed
    all_have_indexes = run.all_samples_have_indexes if run.has_samples else False
    can_export = run.has_samples and all_have_indexes

    return Fieldset(
        Legend("Export"),
        Div(
            Div(
                A(
                    "Download Sample Sheet",
                    href=f"/runs/{run.id}/export/samplesheet",
                    cls=f"btn btn-primary btn-small export-btn {'disabled' if not can_export else ''}",
                ),
                A(
                    "Download JSON",
                    href=f"/runs/{run.id}/export/json",
                    cls="btn btn-secondary btn-small export-btn",
                ),
                cls="export-buttons",
            ),
            cls="export-panel-content",
        ),
        cls="config-panel export-display",
    )
