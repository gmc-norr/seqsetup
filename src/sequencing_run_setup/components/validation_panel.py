"""Validation panel UI components."""

from typing import Optional

from fasthtml.common import *

from ..models.sequencing_run import SequencingRun
from ..models.user import User
from ..models.validation import (
    ColorBalanceStatus,
    DarkCycleError,
    IndexCollision,
    IndexColorBalance,
    IndexDistanceMatrix,
    LaneColorBalance,
    PositionColorBalance,
    SampleDarkCycleInfo,
    ValidationResult,
)
from ..services.validation import ValidationService
from .layout import AppShell


def ValidationPage(run: SequencingRun, user: Optional[User] = None, active_tab: str = "issues"):
    """
    Full validation page wrapped in AppShell with tabbed layout.

    Args:
        run: Sequencing run to validate
        user: Current authenticated user
        active_tab: "issues", "heatmaps", "colorbalance", or "darkcycles"
    """
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
            Span("Validation has issues — resolve before approving", cls="status-error"),
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
        run: Optional SequencingRun needed for dark cycles tab
    """
    error_count = result.error_count
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
                f"Issues ({error_count})" if error_count > 0 else "Issues",
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


def IssuesTabContent(result: ValidationResult):
    """Content for the Issues tab."""
    errors = []

    # Duplicate sample IDs are errors
    for error in result.duplicate_sample_ids:
        errors.append(("duplicate", error))

    # Index collisions are errors
    for collision in result.index_collisions:
        errors.append(("collision", collision))

    # Dark cycle errors
    for dark_err in result.dark_cycle_errors:
        errors.append(("dark_cycle", dark_err))

    if not errors:
        return Div(
            Div(
                Span("✓", cls="status-icon ok"),
                Span("No validation issues detected", cls="status-text"),
                cls="validation-ok",
            ),
            cls="issues-tab-content",
        )

    return Div(
        H3(f"Validation Issues ({len(errors)})"),
        Div(
            *[_render_issue(err_type, err) for err_type, err in errors],
            cls="validation-error-list",
        ),
        cls="issues-tab-content has-errors",
    )


def _render_issue(err_type: str, err):
    """Render a single validation issue item."""
    if err_type == "duplicate":
        return Div(
            Span("Duplicate ID: ", cls="error-type"),
            Span(err),
            cls="validation-error-item",
        )
    elif err_type == "collision":
        return Div(
            IndexCollisionDetail(err),
            cls="validation-error-item",
        )
    elif err_type == "dark_cycle":
        return Div(
            DarkCycleErrorDetail(err),
            cls="validation-error-item",
        )
    return None


def DarkCycleErrorDetail(error: DarkCycleError):
    """Detailed view of a dark cycle error."""
    return Div(
        Span("Dark cycle: ", cls="error-type"),
        Span(f"{error.sample_name}", cls="collision-sample"),
        Span(f" — {error.index_type} index ", cls="collision-vs"),
        Code(error.sequence, cls="sequence"),
        Span(
            f" starts with two dark bases ({error.dark_base}{error.dark_base})",
            cls="collision-distance",
        ),
        cls="dark-cycle-detail",
    )


def HeatmapsTabContent(run_id: str, result: ValidationResult, index_type: str = "i7"):
    """
    Content for the Heatmaps tab with global type controls.

    Args:
        run_id: Run ID for HTMX requests
        result: Validation result with distance matrices
        index_type: "i7", "i5", or "combined"
    """
    if not result.distance_matrices:
        return Div(
            P("No lanes with multiple indexed samples", cls="no-data-message"),
            cls="heatmaps-tab-content",
        )

    # Build heatmap sections for each lane (without individual controls)
    heatmap_sections = []
    for lane in sorted(result.distance_matrices.keys()):
        matrix = result.distance_matrices[lane]
        if len(matrix.sample_names) >= 2:
            heatmap_sections.append(
                LaneHeatmapSimple(lane, matrix, index_type)
            )

    return Div(
        # Global heatmap type controls
        Div(
            Span("Show distances for: ", cls="heatmap-type-label"),
            Button(
                "i7",
                cls="heatmap-toggle active" if index_type == "i7" else "heatmap-toggle",
                hx_get=f"/runs/{run_id}/validation/tab/heatmaps?type=i7",
                hx_target="#validation-tabs",
                hx_swap="outerHTML",
            ),
            Button(
                "i5",
                cls="heatmap-toggle active" if index_type == "i5" else "heatmap-toggle",
                hx_get=f"/runs/{run_id}/validation/tab/heatmaps?type=i5",
                hx_target="#validation-tabs",
                hx_swap="outerHTML",
            ),
            Button(
                "i7+i5",
                cls="heatmap-toggle active" if index_type == "combined" else "heatmap-toggle",
                hx_get=f"/runs/{run_id}/validation/tab/heatmaps?type=combined",
                hx_target="#validation-tabs",
                hx_swap="outerHTML",
            ),
            cls="global-heatmap-controls",
        ),
        P(
            "Lower values (red) indicate potential collision risk.",
            cls="heatmap-description",
        ),
        # All lane heatmaps
        Div(
            *heatmap_sections,
            cls="lane-heatmaps",
        ),
        HeatmapLegend(),
        cls="heatmaps-tab-content",
    )


def LaneHeatmapSimple(lane: int, matrix: IndexDistanceMatrix, index_type: str = "i7"):
    """
    Simple lane heatmap without individual controls (controlled globally).

    Args:
        lane: Lane number
        matrix: Distance matrix data for this lane
        index_type: "i7", "i5", or "combined" to display
    """
    if not matrix or len(matrix.sample_names) < 2:
        return None

    return Div(
        H4(f"Lane {lane}", cls="lane-header"),
        Span(f"({len(matrix.sample_names)} samples)", cls="lane-sample-count"),
        IndexDistanceHeatmap(matrix, index_type),
        cls="lane-heatmap-simple",
    )


def ValidationErrorList(result: ValidationResult):
    """Display validation errors and warnings (legacy, for export panel)."""
    errors = []

    # Duplicate sample IDs are errors
    for error in result.duplicate_sample_ids:
        errors.append(error)

    # Index collisions are errors
    for collision in result.index_collisions:
        errors.append(collision.collision_description)

    # Dark cycle errors
    for dark_err in result.dark_cycle_errors:
        errors.append(dark_err.description)

    if not errors:
        return Div(
            Span("OK", cls="status-icon ok"),
            Span("No validation issues detected", cls="status-text"),
            cls="validation-summary ok",
        )

    return Div(
        H4(f"Validation Issues ({len(errors)})"),
        Ul(
            *[Li(e, cls="validation-error") for e in errors],
            cls="validation-error-list",
        ),
        cls="validation-summary has-errors",
    )


def IndexCollisionDetail(collision: IndexCollision):
    """Detailed view of a single index collision."""
    return Div(
        Span(f"Lane {collision.lane}: ", cls="collision-lane"),
        Span(f"{collision.sample1_name}", cls="collision-sample"),
        Span(" vs ", cls="collision-vs"),
        Span(f"{collision.sample2_name}", cls="collision-sample"),
        Div(
            Span(f"{collision.index_type}: ", cls="collision-index-type"),
            Code(collision.sequence1, cls="sequence"),
            Span(" / ", cls="collision-sep"),
            Code(collision.sequence2, cls="sequence"),
            Span(f" (distance: {collision.hamming_distance})", cls="collision-distance"),
            cls="collision-sequences",
        ),
        cls="collision-detail",
    )


def IndexDistanceHeatmap(matrix: IndexDistanceMatrix, index_type: str = "i7"):
    """
    Render index distances as an HTML table heatmap.

    Args:
        matrix: Distance matrix data
        index_type: "i7", "i5", or "combined" to display
    """
    if not matrix or len(matrix.sample_names) < 2:
        return P("Need at least 2 samples to show heatmap", cls="no-data-message")

    if index_type == "i7":
        distances = matrix.i7_distances
    elif index_type == "i5":
        distances = matrix.i5_distances
    else:  # combined
        distances = matrix.combined_distances
    n = len(matrix.sample_names)

    # Build header row
    header_cells = [Th("", cls="heatmap-corner")]
    for name in matrix.sample_names:
        # Truncate long names
        display_name = name[:8] + ".." if len(name) > 8 else name
        header_cells.append(Th(display_name, cls="heatmap-header", title=name))

    # Build data rows
    rows = [Tr(*header_cells, cls="heatmap-header-row")]

    for i, row_name in enumerate(matrix.sample_names):
        display_name = row_name[:8] + ".." if len(row_name) > 8 else row_name
        row_cells = [Th(display_name, cls="heatmap-row-header", title=row_name)]

        for j in range(n):
            dist = distances[i][j]
            if i == j:
                # Diagonal
                cell_cls = "heatmap-cell diagonal"
                cell_content = "-"
            elif dist is None:
                cell_cls = "heatmap-cell no-data"
                cell_content = "N/A"
            else:
                # Color based on distance (lower = more dangerous = redder)
                dist_class = min(dist, 10)
                cell_cls = f"heatmap-cell dist-{dist_class}"
                cell_content = str(dist)

            row_cells.append(Td(cell_content, cls=cell_cls, title=f"Distance: {dist}"))

        rows.append(Tr(*row_cells))

    return Table(*rows, cls="heatmap-table")


def HeatmapLegend():
    """Color legend for the heatmap."""
    return Div(
        Span("Distance: ", cls="legend-label"),
        Span("0", cls="legend-item dist-0"),
        Span("1", cls="legend-item dist-1"),
        Span("2", cls="legend-item dist-2"),
        Span("3", cls="legend-item dist-3"),
        Span("4+", cls="legend-item dist-4"),
        cls="heatmap-legend",
    )


# Keep these for backward compatibility with routes
def LaneHeatmapSection(run_id: str, lane: int, matrix: IndexDistanceMatrix, index_type: str = "i7"):
    """Legacy: Section containing heatmaps for a single lane."""
    return LaneHeatmapSimple(lane, matrix, index_type)


def LaneHeatmapContent(run_id: str, lane: int, matrix: IndexDistanceMatrix, index_type: str = "i7"):
    """Legacy: Controls and heatmap for a lane."""
    return LaneHeatmapSimple(lane, matrix, index_type)


def ValidationPanel(run: SequencingRun, show_heatmap: bool = True):
    """Legacy: Complete validation panel."""
    result = ValidationService.validate_run(run)
    return ValidationTabs(run.id, result, "issues")


# Color Balance Tab Components

def ColorBalanceTabContent(run_id: str, result: ValidationResult):
    """
    Content for the Color Balance tab.

    Shows per-lane, per-position base distribution for 2-color chemistry analysis.
    """
    # Check if color balance is disabled for this instrument
    if not result.color_balance_enabled:
        return Div(
            Div(
                P(
                    "Color balance analysis is not applicable for this instrument.",
                    cls="info-message",
                ),
                P(
                    "Color balance analysis is only enabled for modern 2-color chemistry "
                    "instruments (e.g., NovaSeq X) where it is critical for successful sequencing. "
                    "It is disabled for older instruments and 4-color chemistry platforms.",
                    cls="info-details",
                ),
                cls="instrument-not-supported-info",
            ),
            cls="colorbalance-tab-content",
        )

    if not result.color_balance:
        return Div(
            P("No indexed samples to analyze", cls="no-data-message"),
            cls="colorbalance-tab-content",
        )

    lane_sections = []
    for lane in sorted(result.color_balance.keys()):
        lane_balance = result.color_balance[lane]
        lane_sections.append(LaneColorBalanceSection(lane_balance))

    # Build description from channel config
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
    else:
        desc_text = (
            "2-color chemistry requires signals in both channels at each position. "
            "Good color balance ensures accurate base calling."
        )

    return Div(
        Div(
            P(desc_text, cls="colorbalance-description"),
            ColorBalanceLegend(result.channel_config),
            cls="colorbalance-header",
        ),
        Div(
            *lane_sections,
            cls="lane-colorbalance-sections",
        ),
        cls="colorbalance-tab-content",
    )


def LaneColorBalanceSection(lane_balance: LaneColorBalance):
    """Section showing color balance for a single lane."""
    status_class = "has-issues" if lane_balance.has_issues else "ok"

    content = []

    if lane_balance.i7_balance:
        content.append(IndexColorBalanceTable(lane_balance.i7_balance))

    if lane_balance.i5_balance:
        content.append(IndexColorBalanceTable(lane_balance.i5_balance))

    if not content:
        content.append(P("No indexed samples in this lane", cls="no-data-message"))

    return Div(
        H4(f"Lane {lane_balance.lane}", cls="lane-header"),
        Span(f"({lane_balance.sample_count} samples)", cls="lane-sample-count"),
        Div(*content, cls="lane-colorbalance-content"),
        cls=f"lane-colorbalance-section {status_class}",
    )


def IndexColorBalanceTable(index_balance: IndexColorBalance):
    """Table showing color balance for all positions of an index type."""
    if not index_balance.positions:
        return None

    # Get channel names from the first position (all positions share same config)
    first_pos = index_balance.positions[0]
    ch1_name = first_pos.channel1_name
    ch2_name = first_pos.channel2_name

    # Header row
    header_cells = [
        Th("Pos", cls="cb-header"),
        Th("A", cls="cb-header base-a"),
        Th("C", cls="cb-header base-c"),
        Th("G", cls="cb-header base-g"),
        Th("T", cls="cb-header base-t"),
        Th(f"{ch1_name} %", cls="cb-header channel-1"),
        Th(f"{ch2_name} %", cls="cb-header channel-2"),
        Th("Status", cls="cb-header"),
    ]

    rows = [Tr(*header_cells, cls="cb-header-row")]

    # Data rows for each position
    for pos in index_balance.positions:
        status_cls = f"status-{pos.status.value}"
        status_icon = "✓" if pos.status == ColorBalanceStatus.OK else (
            "⚠" if pos.status == ColorBalanceStatus.WARNING else "✗"
        )

        row_cells = [
            Td(str(pos.position), cls="cb-cell position"),
            Td(str(pos.a_count), cls="cb-cell base-a"),
            Td(str(pos.c_count), cls="cb-cell base-c"),
            Td(str(pos.g_count), cls="cb-cell base-g"),
            Td(str(pos.t_count), cls="cb-cell base-t"),
            Td(f"{pos.channel1_percent:.0f}%", cls=f"cb-cell channel-1 {_channel_class(pos.channel1_percent)}"),
            Td(f"{pos.channel2_percent:.0f}%", cls=f"cb-cell channel-2 {_channel_class(pos.channel2_percent)}"),
            Td(status_icon, cls=f"cb-cell status {status_cls}"),
        ]
        rows.append(Tr(*row_cells, cls=f"cb-row {status_cls}"))

    return Div(
        H5(f"{index_balance.index_type.upper()} Index", cls="index-type-header"),
        Table(*rows, cls="colorbalance-table"),
        cls="index-colorbalance",
    )


def _channel_class(percent: float) -> str:
    """Get CSS class for a channel percentage."""
    if percent >= 50:
        return "channel-high"
    elif percent >= 25:
        return "channel-medium"
    elif percent > 0:
        return "channel-low"
    return "channel-zero"


def ColorBalanceLegend(channel_config: Optional[dict] = None):
    """Legend explaining the color balance display."""
    if channel_config:
        ch1_name = channel_config["channel1_name"]
        ch1_bases = "+".join(channel_config["channel1_bases"])
        ch2_name = channel_config["channel2_name"]
        ch2_bases = "+".join(channel_config["channel2_bases"])
    else:
        ch1_name = "Channel 1"
        ch1_bases = "A+C"
        ch2_name = "Channel 2"
        ch2_bases = "C+T"

    return Div(
        Div(
            Span("Channels: ", cls="legend-label"),
            Span(f"{ch1_name} ({ch1_bases})", cls="legend-item channel-1-demo"),
            Span(f"{ch2_name} ({ch2_bases})", cls="legend-item channel-2-demo"),
            cls="legend-section",
        ),
        Div(
            Span("Status: ", cls="legend-label"),
            Span("✓ OK", cls="legend-item status-ok"),
            Span("⚠ Warning (<25%)", cls="legend-item status-warning"),
            Span("✗ Error (0%)", cls="legend-item status-error"),
            cls="legend-section",
        ),
        cls="colorbalance-legend",
    )


# Dark Cycles Tab Components

def DarkCyclesTabContent(run_id: str, result: ValidationResult):
    """
    Content for the Dark Cycles tab.

    Shows a visual representation of each sample's index sequences with
    dark bases highlighted. Warns when two consecutive dark bases appear
    at the start of an index.
    """
    if not result.color_balance_enabled:
        return Div(
            Div(
                P(
                    "Dark cycle analysis is not applicable for this instrument.",
                    cls="info-message",
                ),
                P(
                    "Dark cycle analysis is only relevant for 2-color chemistry instruments "
                    "where a dark base (producing no signal in either channel) can cause issues "
                    "if the first two bases of an index are both dark.",
                    cls="info-details",
                ),
                cls="instrument-not-supported-info",
            ),
            cls="darkcycles-tab-content",
        )

    samples = result.dark_cycle_samples
    if not samples:
        return Div(
            P("No indexed samples to analyze", cls="no-data-message"),
            cls="darkcycles-tab-content",
        )

    dark_base = samples[0].dark_base
    cc = result.channel_config
    if cc:
        ch1_bases = ", ".join(cc["channel1_bases"])
        ch2_bases = ", ".join(cc["channel2_bases"])
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

    # Count issues
    error_count = sum(1 for s in samples if s.i7_leading_dark >= 2 or s.i5_leading_dark >= 2)
    warning_count = sum(1 for s in samples if (s.i7_leading_dark == 1 or s.i5_leading_dark == 1)
                        and s.i7_leading_dark < 2 and s.i5_leading_dark < 2)

    status_summary = []
    if error_count > 0:
        status_summary.append(Span(f"{error_count} error(s)", cls="dc-summary-error"))
    if warning_count > 0:
        status_summary.append(Span(f"{warning_count} warning(s)", cls="dc-summary-warning"))
    if not status_summary:
        status_summary.append(Span("No dark cycle issues", cls="dc-summary-ok"))

    return Div(
        Div(
            P(desc_text, cls="darkcycles-description"),
            Div(*status_summary, cls="dc-summary"),
            DarkCyclesLegend(dark_base),
            cls="darkcycles-header",
        ),
        DarkCyclesTable(samples),
        cls="darkcycles-tab-content",
    )


def DarkCyclesTable(samples: list[SampleDarkCycleInfo]):
    """Table showing dark cycle analysis for all samples."""
    header_cells = [
        Th("Sample", cls="dc-header"),
        Th("i7 Index", cls="dc-header"),
        Th("i7 Status", cls="dc-header"),
        Th("i5 Index", cls="dc-header"),
        Th("i5 Status", cls="dc-header"),
    ]
    rows = [Tr(*header_cells, cls="dc-header-row")]

    for sample in samples:
        # Determine row-level status
        has_error = sample.i7_leading_dark >= 2 or sample.i5_leading_dark >= 2
        has_warning = (not has_error and
                       (sample.i7_leading_dark == 1 or sample.i5_leading_dark == 1))
        row_cls = "dc-row"
        if has_error:
            row_cls += " dc-row-error"
        elif has_warning:
            row_cls += " dc-row-warning"

        # i7 sequence visualization
        if sample.i7_sequence:
            i7_viz = _dark_cycle_sequence_viz(sample.i7_sequence, sample.dark_base)
            i7_status = _dark_cycle_status(sample.i7_leading_dark)
        else:
            i7_viz = Span("—", cls="no-index")
            i7_status = Span("—", cls="no-index")

        # i5 sequence visualization (show read orientation)
        if sample.i5_sequence:
            i5_viz = _dark_cycle_sequence_viz(sample.i5_read_sequence, sample.dark_base)
            i5_status = _dark_cycle_status(sample.i5_leading_dark)
        else:
            i5_viz = Span("—", cls="no-index")
            i5_status = Span("—", cls="no-index")

        rows.append(Tr(
            Td(sample.sample_name, cls="dc-cell dc-sample"),
            Td(i7_viz, cls="dc-cell dc-sequence"),
            Td(i7_status, cls="dc-cell dc-status"),
            Td(i5_viz, cls="dc-cell dc-sequence"),
            Td(i5_status, cls="dc-cell dc-status"),
            cls=row_cls,
        ))

    return Table(*rows, cls="darkcycles-table")


def _dark_cycle_sequence_viz(sequence: str, dark_base: str):
    """
    Render a sequence with each base color-coded.
    Dark bases are highlighted. The first two positions are marked specially.
    """
    if not sequence:
        return Span("—")

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

        bases.append(Span(base.upper(), cls=" ".join(cls_parts)))

    return Span(*bases, cls="dc-sequence-viz")


def _dark_cycle_status(leading_dark: int):
    """Return a status indicator for the number of leading dark bases."""
    if leading_dark >= 2:
        return Span("Error — two dark", cls="dc-status-error")
    elif leading_dark == 1:
        return Span("OK — one dark", cls="dc-status-warning")
    return Span("OK", cls="dc-status-ok")


def DarkCyclesLegend(dark_base: str):
    """Legend for the dark cycles visualization."""
    return Div(
        Div(
            Span("Base colors: ", cls="legend-label"),
            Span(f"{dark_base} (dark)", cls="legend-item dc-legend-dark"),
            Span("Other bases", cls="legend-item dc-legend-normal"),
            cls="legend-section",
        ),
        Div(
            Span("Status: ", cls="legend-label"),
            Span("OK", cls="legend-item dc-status-ok"),
            Span("OK — one dark leading", cls="legend-item dc-status-warning"),
            Span("Error — two dark leading", cls="legend-item dc-status-error"),
            cls="legend-section",
        ),
        cls="darkcycles-legend",
    )
